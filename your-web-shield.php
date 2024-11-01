<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly
}

/**
 * Plugin Name: Your Web Shield
 * Plugin URI: https://yourpluginwebsite.com
 * Description: A plugin that checks and blocks risky IPs with rate limiting, WAF, and syncs machine learning model.
 * Version: 1.2
 * Author: Petersweb
 * License: GPL-2.0+
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

register_activation_hook(__FILE__, 'yourwebshield_activate');
function yourwebshield_activate() {
    yourwebshield_create_table();
    add_option('yourwebshield_risk_threshold', 70);
    add_option('yourwebshield_max_requests', 100);
    add_option('yourwebshield_window_ms', 900); // Default 900 seconds (15 minutes)
    add_option('yourwebshield_waf_enabled', 1); // Enable WAF by default
    add_option('yourwebshield_waf_sql_enabled', 1); // Enable SQL Injection rule by default
    add_option('yourwebshield_waf_xss_enabled', 1); // Enable XSS rule by default
    add_option('yourwebshield_waf_common_enabled', 1); // Enable Common Attack Patterns rule by default
}

// Create the database table for IP tracking
function yourwebshield_create_table() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'yourwebshield_ips';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE IF NOT EXISTS $table_name (
        id mediumint(9) NOT NULL AUTO_INCREMENT,
        ip_address varchar(100) NOT NULL,
        risk_score int NOT NULL,
        checked_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
        page_accessed varchar(255) DEFAULT '' NOT NULL,
        reported tinyint(1) DEFAULT 0 NOT NULL,  // New column to track if IP was reported
        PRIMARY KEY (id)
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
}

/**
 * Register the cron event to send logged IPs every 5 minutes.
 */
register_activation_hook(__FILE__, 'yourwebshield_schedule_send_ips_event');
function yourwebshield_schedule_send_ips_event() {
    if (! wp_next_scheduled('yourwebshield_send_logged_ips_event')) {
        wp_schedule_event(time(), 'five_minutes', 'yourwebshield_send_logged_ips_event');
    }
}

/**
 * Clear the cron event when plugin is deactivated.
 */
register_deactivation_hook(__FILE__, 'yourwebshield_clear_send_ips_event');
function yourwebshield_clear_send_ips_event() {
    $timestamp = wp_next_scheduled('yourwebshield_send_logged_ips_event');
    if ($timestamp) {
        wp_unschedule_event($timestamp, 'yourwebshield_send_logged_ips_event');
    }
}

/**
 * Add a custom interval of 5 minutes.
 */
add_filter('cron_schedules', 'yourwebshield_add_five_minute_cron_interval');
function yourwebshield_add_five_minute_cron_interval($schedules) {
    $schedules['five_minutes'] = array(
        'interval' => 300, // 300 seconds = 5 minutes
        'display' => __('Every 5 Minutes')
    );
    return $schedules;
}

/**
 * Hook the function to the cron event.
 */
add_action('yourwebshield_send_logged_ips_event', 'yourwebshield_send_logged_ips');

/**
 * Function to send logged IPs to the external API.
 * Only sends IPs that have not been reported yet.
 */
function yourwebshield_send_logged_ips() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'yourwebshield_ips';

    // Fetch only IPs that haven't been reported
    $logged_ips = $wpdb->get_results("SELECT id, ip_address, risk_score, checked_at, page_accessed FROM $table_name WHERE reported = 0");

    if (!empty($logged_ips)) {
        // Prepare the data to be sent
        $ips_to_send = array_map(function ($row) {
            return array(
                'ip_address'    => $row->ip_address,
                'risk_score'    => $row->risk_score,
                'checked_at'    => $row->checked_at,
                'page_accessed' => $row->page_accessed,
            );
        }, $logged_ips);

        // Send the IPs data to the external API via POST request
    
        $response = wp_remote_post('http://127.0.0.1:5000/api/wp/update', array(
            'method'    => 'POST',
            'headers'   => array('Content-Type' => 'application/json'),
            'body'      => json_encode($ips_to_send),
            'timeout'   => 45,
        ));

        // Check if the request was successful
        if (is_wp_error($response)) {
            error_log('Failed to send logged IPs: ' . $response->get_error_message());
        } else {
            error_log('Logged IPs successfully sent to the API.');

            // Mark IPs as reported after successful API response
            foreach ($logged_ips as $ip) {
                $wpdb->update(
                    $table_name,
                    array('reported' => 1), // Mark as reported
                    array('id' => $ip->id)
                );
            }
        }
    }
}

// Hardcoded URL for WAF rules JSON
function yourwebshield_get_waf_rules() {
    $waf_url = 'http://127.0.0.1:5000/api/wp/wafupdate'; // HARDCODED WAF RULES URL

    // Fetch the WAF rules JSON
    $response = wp_remote_get($waf_url);
    if (is_wp_error($response)) {
        error_log('Failed to fetch WAF rules: ' . $response->get_error_message());
        return false;
    }

    $body = wp_remote_retrieve_body($response);
    $waf_rules = json_decode($body, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log('Invalid WAF rules JSON.');
        return false;
    }

    return $waf_rules;
}

// Default WAF patterns (used if dynamic WAF fetching fails)
function yourwebshield_default_waf_rules() {
    return array(
        'sql_patterns' => array('/select.*from/i', '/union.*select/i'),
        'xss_patterns' => array('/<script.*?>.*<\/script>/i'),
        'common_attack_patterns' => array('/etc\/passwd/i', '/\.\.\//', '/base64_decode/i'),
    );
}

// WAF: Check for attack patterns based on dynamic rules
function yourwebshield_waf($request_uri) {
    if (get_option('yourwebshield_waf_enabled', 1) != 1) {
        return 0; // WAF is disabled
    }

    // Fetch the WAF rules (fallback to default rules if unavailable)
    $waf_rules = yourwebshield_get_waf_rules();
    if (!$waf_rules) {
        $waf_rules = yourwebshield_default_waf_rules();
    }

    $risk_increase = 0;

    // Check SQL Injection patterns if enabled
    if (get_option('yourwebshield_waf_sql_enabled', 1)) {
        foreach ($waf_rules['sql_patterns'] as $pattern) {
            if (preg_match($pattern, $request_uri)) {
                $risk_increase += 20;
                error_log("SQL Injection attempt detected.");
            }
        }
    }

    // Check XSS patterns if enabled
    if (get_option('yourwebshield_waf_xss_enabled', 1)) {
        foreach ($waf_rules['xss_patterns'] as $pattern) {
            if (preg_match($pattern, $request_uri)) {
                $risk_increase += 20;
                error_log("XSS attempt detected.");
            }
        }
    }

    // Check common attack patterns if enabled
    if (get_option('yourwebshield_waf_common_enabled', 1)) {
        foreach ($waf_rules['common_attack_patterns'] as $pattern) {
            if (preg_match($pattern, $request_uri)) {
                $risk_increase += 15;
                error_log("Common attack pattern detected.");
            }
        }
    }

    return $risk_increase;
}

// Check IP on every request
function yourwebshield_check_ip() {
    if (isset($_SERVER['REMOTE_ADDR'])) {
        $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        $ip = filter_var($ip, FILTER_VALIDATE_IP);

        if ($ip === false) {
            wp_die('Invalid IP address.', 'Invalid Request', array('response' => 400));
        }

        // Rate limiting logic
        global $wpdb;
        $request_count = get_transient('yourwebshield_ip_' . $ip);
        $max_requests = get_option('yourwebshield_max_requests', 100);
        $window_time = get_option('yourwebshield_window_ms', 900);

        if ($request_count === false) {
            $request_count = 0;
            set_transient('yourwebshield_ip_' . $ip, $request_count, $window_time);
        }

        if ($request_count >= $max_requests) {
            wp_die('Too many requests from this IP, please try again later.', 'Too Many Requests', array('response' => 429));
        }

        set_transient('yourwebshield_ip_' . $ip, $request_count + 1, $window_time);

        // Assume all IPs start with a baseline risk score of 0
        $risk_score = 0;

        // WAF check (if enabled)
        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $risk_score += yourwebshield_waf($request_uri);

        // Fetch the IP data from the database
        $table_name = $wpdb->prefix . 'yourwebshield_ips';
        $ip_data = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table_name WHERE ip_address = %s", $ip));

        if ($ip_data) {
            // Update the existing IP record if necessary
            if ($risk_score > $ip_data->risk_score) {
                $wpdb->update($table_name, array('risk_score' => $risk_score), array('id' => $ip_data->id));
            }
        } else {
            // Insert a new IP record if it doesn't exist
            $wpdb->insert($table_name, array(
                'ip_address' => $ip,
                'risk_score' => $risk_score,
                'checked_at' => current_time('mysql'),
                'page_accessed' => $request_uri,
            ));
        }

        // Handle risky IPs
        $risk_threshold = get_option('yourwebshield_risk_threshold', 70);
        if ($risk_score >= $risk_threshold) {
            wp_die('Access denied due to security concerns.', 'Forbidden', array('response' => 403));
        }
    }
}

add_action('init', 'yourwebshield_check_ip');


add_action('template_redirect', 'yourwebshield_check_ip');

// Admin settings page
add_action('admin_menu', 'yourwebshield_menu');
function yourwebshield_menu() {
    add_menu_page('Your Web Shield Settings', 'Your Web Shield', 'manage_options', 'yourwebshield_settings', 'yourwebshield_settings_page');
}

// Settings page content
function yourwebshield_settings_page() {
    global $wpdb;

    // Handle form submission for settings
    if (isset($_POST['yourwebshield_settings_nonce_field']) &&
        wp_verify_nonce($_POST['yourwebshield_settings_nonce_field'], 'yourwebshield_settings_nonce')) {

        update_option('yourwebshield_risk_threshold', sanitize_text_field($_POST['yourwebshield_risk_threshold']));
        update_option('yourwebshield_max_requests', sanitize_text_field($_POST['yourwebshield_max_requests']));
        update_option('yourwebshield_window_ms', sanitize_text_field($_POST['yourwebshield_window_ms']));
        
        // WAF Rules toggles
        update_option('yourwebshield_waf_enabled', isset($_POST['yourwebshield_waf_enabled']) ? 1 : 0);
        update_option('yourwebshield_waf_sql_enabled', isset($_POST['yourwebshield_waf_sql_enabled']) ? 1 : 0);
        update_option('yourwebshield_waf_xss_enabled', isset($_POST['yourwebshield_waf_xss_enabled']) ? 1 : 0);
        update_option('yourwebshield_waf_common_enabled', isset($_POST['yourwebshield_waf_common_enabled']) ? 1 : 0);
    }

    // Get IP records from the database
    $table_name = $wpdb->prefix . 'yourwebshield_ips';
    $ips = $wpdb->get_results("SELECT * FROM $table_name ORDER BY checked_at DESC");

    ?>
    <div class="wrap">
        <h1>Your Web Shield Settings</h1>
        
        <form method="post" action="">
            <?php wp_nonce_field('yourwebshield_settings_nonce', 'yourwebshield_settings_nonce_field'); ?>

            <h2>General Settings</h2>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row">Risk Threshold</th>
                    <td><input type="number" name="yourwebshield_risk_threshold" value="<?php echo esc_attr(get_option('yourwebshield_risk_threshold')); ?>"></td>
                </tr>

                <tr valign="top">
                    <th scope="row">Max Requests</th>
                    <td><input type="number" name="yourwebshield_max_requests" value="<?php echo esc_attr(get_option('yourwebshield_max_requests')); ?>"></td>
                </tr>

                <tr valign="top">
                    <th scope="row">Time Window (seconds)</th>
                    <td><input type="number" name="yourwebshield_window_ms" value="<?php echo esc_attr(get_option('yourwebshield_window_ms')); ?>"></td>
                </tr>

                <tr valign="top">
                    <th scope="row">WAF Enabled</th>
                    <td><input type="checkbox" name="yourwebshield_waf_enabled" value="1" <?php checked(1, get_option('yourwebshield_waf_enabled'), true); ?>></td>
                </tr>

                <tr valign="top">
                    <th scope="row">SQL Injection Protection</th>
                    <td><input type="checkbox" name="yourwebshield_waf_sql_enabled" value="1" <?php checked(1, get_option('yourwebshield_waf_sql_enabled'), true); ?>></td>
                </tr>

                <tr valign="top">
                    <th scope="row">XSS Protection</th>
                    <td><input type="checkbox" name="yourwebshield_waf_xss_enabled" value="1" <?php checked(1, get_option('yourwebshield_waf_xss_enabled'), true); ?>></td>
                </tr>

                <tr valign="top">
                    <th scope="row">Common Attack Patterns</th>
                    <td><input type="checkbox" name="yourwebshield_waf_common_enabled" value="1" <?php checked(1, get_option('yourwebshield_waf_common_enabled'), true); ?>></td>
                </tr>
            </table>

            <input type="submit" value="Save Settings" class="button-primary">
        </form>

        <h2>Logged IPs</h2>
        <table class="widefat fixed" cellspacing="0">
            <thead>
                <tr>
                    <th scope="col">IP Address</th>
                    <th scope="col">Risk Score</th>
                    <th scope="col">Checked At</th>
                    <th scope="col">Page Accessed</th>
                </tr>
            </thead>
            <tbody>
                <?php if ($ips): ?>
                    <?php foreach ($ips as $ip): ?>
                        <tr>
                            <td><?php echo esc_html($ip->ip_address); ?></td>
                            <td><?php echo esc_html($ip->risk_score); ?></td>
                            <td><?php echo esc_html($ip->checked_at); ?></td>
                            <td><?php echo esc_html($ip->page_accessed); ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php else: ?>
                    <tr>
                        <td colspan="4">No logged IPs found.</td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
    <?php
}
?>