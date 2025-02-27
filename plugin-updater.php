<?php
/**
 * GitHub Plugin Updater
 *
 * This class handles automatic updates for the AQM Form Security plugin
 * by checking for new versions on GitHub and providing update information to WordPress.
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

class AQM_Plugin_Updater {
    private $slug;
    private $plugin_data;
    private $username;
    private $repo;
    private $plugin_file;
    private $github_api_result;

    /**
     * Class constructor.
     *
     * @param string $plugin_file Path to the plugin file
     * @param string $github_username GitHub username
     * @param string $github_repo GitHub repo name
     * @param string $access_token GitHub access token (optional, not needed for public repos)
     */
    public function __construct($plugin_file, $github_username, $github_repo, $access_token = '') {
        $this->plugin_file = $plugin_file;
        $this->username = $github_username;
        $this->repo = $github_repo;

        add_filter('pre_set_site_transient_update_plugins', array($this, 'check_update'));
        add_filter('plugins_api', array($this, 'plugin_popup'), 10, 3);
        add_filter('upgrader_post_install', array($this, 'after_install'), 10, 3);
        
        // Add row action to check for updates
        add_filter('plugin_action_links_' . plugin_basename($plugin_file), array($this, 'add_check_update_link'));
        
        // Handle manual update check
        add_action('admin_init', array($this, 'handle_manual_update_check'));
        
        // Get plugin data
        $this->plugin_data = get_plugin_data($plugin_file);
        $this->slug = plugin_basename($plugin_file);
    }

    /**
     * Add "Check for Updates" link to plugin actions
     *
     * @param array $links Existing plugin action links
     * @return array Modified plugin action links
     */
    public function add_check_update_link($links) {
        $check_update_url = wp_nonce_url(
            add_query_arg(
                array(
                    'aqm_check_update' => 'true',
                    'plugin' => plugin_basename($this->plugin_file)
                ),
                admin_url('plugins.php')
            ),
            'aqm_check_update_nonce'
        );
        
        $links[] = '<a href="' . esc_url($check_update_url) . '">' . __('Check for Updates', 'aqm-formidable-spam-blocker') . '</a>';
        
        return $links;
    }

    /**
     * Handle manual update check
     */
    public function handle_manual_update_check() {
        if (isset($_GET['aqm_check_update']) && $_GET['aqm_check_update'] === 'true' && 
            isset($_GET['plugin']) && $_GET['plugin'] === plugin_basename($this->plugin_file)) {
            
            // Verify nonce
            if (!isset($_GET['_wpnonce']) || !wp_verify_nonce($_GET['_wpnonce'], 'aqm_check_update_nonce')) {
                wp_die(__('Security check failed', 'aqm-formidable-spam-blocker'));
            }
            
            // Clear the plugin update cache
            delete_site_transient('update_plugins');
            
            // Redirect back to the plugins page
            wp_redirect(admin_url('plugins.php?aqm_update_checked=true'));
            exit;
        }
        
        // Show admin notice after checking for updates
        if (isset($_GET['aqm_update_checked']) && $_GET['aqm_update_checked'] === 'true') {
            add_action('admin_notices', array($this, 'update_check_notice'));
        }
    }

    /**
     * Display admin notice after checking for updates
     */
    public function update_check_notice() {
        ?>
        <div class="notice notice-success is-dismissible">
            <p><?php _e('AQM Form Security plugin has checked for updates.', 'aqm-formidable-spam-blocker'); ?></p>
        </div>
        <?php
    }

    /**
     * Get repository info from GitHub
     *
     * @return array|bool Repository info or false on failure
     */
    private function get_repository_info() {
        if (!empty($this->github_api_result)) {
            return $this->github_api_result;
        }

        // Query the GitHub API
        $url = "https://api.github.com/repos/{$this->username}/{$this->repo}/releases/latest";
        
        // Get the results
        $response = wp_remote_get($url);
        
        // Check for errors
        if (is_wp_error($response) || 200 !== wp_remote_retrieve_response_code($response)) {
            return false;
        }
        
        $response = json_decode(wp_remote_retrieve_body($response));
        
        // Check if valid response
        if (empty($response)) {
            return false;
        }
        
        // Store API result for future calls
        $this->github_api_result = $response;
        
        return $response;
    }

    /**
     * Check for plugin updates
     *
     * @param object $transient WordPress update transient
     * @return object Modified update transient
     */
    public function check_update($transient) {
        // If no check has been done, return without checking
        if (empty($transient->checked)) {
            return $transient;
        }
        
        // Get plugin version
        $plugin_version = $this->plugin_data['Version'];
        
        // Get GitHub release info
        $release_info = $this->get_repository_info();
        
        // If there's no release info or error, return unchanged
        if (empty($release_info)) {
            return $transient;
        }
        
        // Check if a new version is available
        // Remove 'v' prefix if present in tag name
        $github_version = ltrim($release_info->tag_name, 'v');
        
        // Compare versions
        if (version_compare($github_version, $plugin_version, '>')) {
            // Find the ZIP file URL in assets
            $download_url = '';
            
            // First try to find a ZIP asset
            if (!empty($release_info->assets)) {
                foreach ($release_info->assets as $asset) {
                    if (strpos($asset->name, '.zip') !== false) {
                        $download_url = $asset->browser_download_url;
                        break;
                    }
                }
            }
            
            // If no ZIP asset found, use the source code ZIP - BUT ONLY AS LAST RESORT
            // Prefer to use the clean release asset created by GitHub Actions
            if (empty($download_url) && isset($release_info->zipball_url)) {
                // Log that we're using the source code ZIP as a fallback
                error_log('AQM Plugin Updater: No release asset found, falling back to source code ZIP');
                $download_url = $release_info->zipball_url;
            }
            
            // Build the update object
            if (!empty($download_url)) {
                $obj = new stdClass();
                $obj->slug = $this->slug;
                $obj->new_version = $github_version;
                $obj->url = $this->plugin_data['PluginURI'];
                $obj->package = $download_url;
                $obj->tested = isset($release_info->tested) ? $release_info->tested : '';
                $obj->requires = isset($release_info->requires) ? $release_info->requires : '';
                $obj->requires_php = isset($release_info->requires_php) ? $release_info->requires_php : '';
                
                // Add to transient
                $transient->response[$this->slug] = $obj;
            }
        }
        
        return $transient;
    }

    /**
     * Provide plugin information for the WordPress updates screen
     *
     * @param false|object|array $result The result object or array
     * @param string $action The API action being performed
     * @param object $args Plugin API arguments
     * @return object Plugin information
     */
    public function plugin_popup($result, $action, $args) {
        // If this is not about getting plugin information, bail
        if ('plugin_information' !== $action) {
            return $result;
        }
        
        // If it's not our plugin, bail
        if (!isset($args->slug) || $args->slug !== dirname($this->slug)) {
            return $result;
        }
        
        // Get GitHub release info
        $release_info = $this->get_repository_info();
        
        // If there's no release info or error, return unchanged
        if (empty($release_info)) {
            return $result;
        }
        
        // Create plugin info object
        $plugin_info = new stdClass();
        $plugin_info->name = $this->plugin_data['Name'];
        $plugin_info->slug = dirname($this->slug);
        $plugin_info->version = ltrim($release_info->tag_name, 'v');
        $plugin_info->author = $this->plugin_data['Author'];
        $plugin_info->homepage = $this->plugin_data['PluginURI'];
        $plugin_info->requires = isset($release_info->requires) ? $release_info->requires : '';
        $plugin_info->tested = isset($release_info->tested) ? $release_info->tested : '';
        $plugin_info->requires_php = isset($release_info->requires_php) ? $release_info->requires_php : '';
        $plugin_info->downloaded = 0;
        
        // Set the description and changelog
        $plugin_info->sections = array(
            'description' => $this->plugin_data['Description'],
            'changelog' => nl2br($release_info->body)
        );
        
        // Find the ZIP file URL in assets
        $download_url = '';
        
        // First try to find a ZIP asset
        if (!empty($release_info->assets)) {
            foreach ($release_info->assets as $asset) {
                if (strpos($asset->name, '.zip') !== false) {
                    $download_url = $asset->browser_download_url;
                    break;
                }
            }
        }
        
        // If no ZIP asset found, use the source code ZIP - BUT ONLY AS LAST RESORT
        // Prefer to use the clean release asset created by GitHub Actions
        if (empty($download_url) && isset($release_info->zipball_url)) {
            // Log that we're using the source code ZIP as a fallback
            error_log('AQM Plugin Updater: No release asset found, falling back to source code ZIP');
            $download_url = $release_info->zipball_url;
        }
        
        $plugin_info->download_link = $download_url;
        
        return $plugin_info;
    }

    /**
     * Rename the plugin directory after installation
     *
     * @param bool $response Installation response
     * @param array $hook_extra Extra arguments passed to hooked filters
     * @param array $result Installation result data
     * @return array Modified installation result data
     */
    public function after_install($response, $hook_extra, $result) {
        global $wp_filesystem;
        
        // If this is not our plugin, bail
        if (!isset($hook_extra['plugin']) || $hook_extra['plugin'] !== $this->slug) {
            return $result;
        }
        
        // Get the plugin directory name
        $plugin_dir = dirname($result['destination']);
        $plugin_folder = dirname($this->slug);
        
        // If the plugin folder doesn't match the slug, rename it
        if (basename($result['destination']) !== $plugin_folder) {
            $new_destination = trailingslashit($plugin_dir) . $plugin_folder;
            
            // Remove the new destination if it exists
            if ($wp_filesystem->exists($new_destination)) {
                $wp_filesystem->delete($new_destination, true);
            }
            
            // Rename the folder
            $wp_filesystem->move($result['destination'], $new_destination);
            $result['destination'] = $new_destination;
            
            // Activate the plugin
            activate_plugin($this->slug);
        }
        
        return $result;
    }
}
