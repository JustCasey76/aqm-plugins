<?php
// This script fixes the duplicate function issue

$file = __DIR__ . '/aqm-formidable-spam-blocker.php';
$content = file_get_contents($file);

// Count occurrences of the function declaration
$count = substr_count($content, 'function clear_geo_cache()');
echo "Found {$count} occurrences of clear_geo_cache() function\n";

// Find the position of the second occurrence
if ($count > 1) {
    $first_pos = strpos($content, 'function clear_geo_cache()');
    $second_pos = strpos($content, 'function clear_geo_cache()', $first_pos + 1);
    
    if ($second_pos !== false) {
        // Find the end of the function (closing brace)
        $start_braces = 1;
        $end_pos = $second_pos;
        
        // Start looking for the end of the function after the function declaration
        $func_decl_end = strpos($content, '{', $second_pos) + 1;
        
        for ($i = $func_decl_end; $i < strlen($content); $i++) {
            if ($content[$i] === '{') {
                $start_braces++;
            } elseif ($content[$i] === '}') {
                $start_braces--;
                if ($start_braces === 0) {
                    $end_pos = $i + 1;
                    break;
                }
            }
        }
        
        // Get text before and after the duplicate function
        $before = substr($content, 0, $second_pos);
        $function_text = substr($content, $second_pos, $end_pos - $second_pos);
        $after = substr($content, $end_pos);
        
        echo "Found second occurrence at position {$second_pos}, ending at {$end_pos}\n";
        echo "Function text length: " . strlen($function_text) . "\n";
        
        // Find the line with register_settings handler
        $register_line = "// Register the standalone settings handler\nadd_action('admin_post_ffb_save_settings', 'handle_save_settings');";
        
        // Replace the duplicate function with just the register line
        $new_content = $before . $register_line . $after;
        
        // Ensure we actually modified the content
        if ($new_content !== $content) {
            // Backup the original file first
            copy($file, $file . '.bak');
            
            // Write the modified content
            if (file_put_contents($file, $new_content)) {
                echo "Successfully removed duplicate function and saved file.\n";
            } else {
                echo "Failed to write to file.\n";
            }
        } else {
            echo "Content was not modified.\n";
        }
    } else {
        echo "Could not find second occurrence.\n";
    }
} else {
    echo "Only found one occurrence. No fix needed.\n";
}
