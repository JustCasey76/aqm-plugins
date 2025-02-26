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
        
        // Get plugin data
        $this->plugin_data = get_plugin_data($plugin_file);
        $this->slug = plugin_basename($plugin_file);
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
            
            // If no ZIP asset found, use the source code ZIP
            if (empty($download_url)) {
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
        
        // If no ZIP asset found, use the source code ZIP
        if (empty($download_url)) {
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
