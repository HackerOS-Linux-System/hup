require "process"
require "file"
require "dir"
require "yaml"
require "json"
require "http/client"
require "logger"

# Simple ANSI color codes
COLOR_CODES = {
  "black"   => "\e[30m",
  "red"     => "\e[31m",
  "green"   => "\e[32m",
  "yellow"  => "\e[33m",
  "blue"    => "\e[34m",
  "magenta" => "\e[35m",
  "cyan"    => "\e[36m",
  "white"   => "\e[37m",
  "reset"   => "\e[0m",
}

# Default config
DEFAULT_CONFIG = {
  "apt" => {
    "enabled" => true,
    "upgrade" => true,
    "dist_upgrade" => false,
    "autoremove" => true,
    "autoclean" => true,
  },
  "flatpak" => {
    "enabled" => true,
  },
  "fwupd" => {
    "enabled" => false,
  },
  "snap" => {
    "enabled" => false,
  },
  "notify" => {
    "enabled" => true,
    "reboot_message" => "HackerOS: Reboot required after updates!",
  },
  "log" => {
    "file" => "/var/log/hup.log",
    "level" => "info",
  },
  "style" => {
    "info_color" => "cyan",
    "error_color" => "red",
    "success_color" => "green",
  },
}

# Simple CSS parser for style config
def parse_css(file_path : String) : Hash(String, String)
  styles = Hash(String, String).new
  if File.exists?(file_path)
    File.each_line(file_path) do |line|
      line = line.strip
      next if line.empty? || line.starts_with?("//") || line.starts_with?("/*")
      if line.includes?(":")
        key, value = line.split(":", 2).map(&.strip).map(&.gsub(";", ""))
        styles[key] = value
      end
    end
  end
  styles
end

# Run shell command with output capture
def run_command(cmd : String, args : Array(String), log : Logger) : {Bool, String, String}
  process = Process.new(cmd, args, output: Process::Redirect::Pipe, error: Process::Redirect::Pipe)
  status = process.wait
  out = process.output.gets_to_end
  err = process.error.gets_to_end
  if status.success?
    log.info("Command '#{cmd} #{args.join(" ")}' succeeded: #{out}")
  else
    log.error("Command '#{cmd} #{args.join(" ")}' failed: #{err}")
  end
  {status.success?, out, err}
end

# Get current Debian version and codename
def get_current_debian_info : {String, String}
  if File.exists?("/etc/os-release")
    content = File.read("/etc/os-release")
    version = content.match(/VERSION_ID="(\d+)"/).try(&.[1]) || "unknown"
    codename = content.match(/PRETTY_NAME=".*\((.*?)\)"$/).try(&.[1]) || "unknown"
    {version, codename}
  else
    {"unknown", "unknown"}
  end
end

# Save current version to JSON
def save_current_version(version : String, codename : String)
  dir = "/var/cache/hup"
  Dir.mkdir_p(dir) unless Dir.exists?(dir)
  file = File.new("#{dir}/version.json", "w")
  json = {
    "version"  => version,
    "codename" => codename,
  }.to_json
  file.print(json)
  file.close
end

# Check if reboot is required
def reboot_required? : Bool
  File.exists?("/var/run/reboot-required")
end

# Send desktop notification
def send_notification(message : String, log : Logger)
  success, _, err = run_command("notify-send", ["-u", "critical", "Hacker Updater", message], log)
  unless success
    log.error("Notification failed: #{err}")
  end
end

# Update APT
def update_apt(config : Hash, log : Logger, current_codename : String) : Bool
  return true unless config["apt"]["enabled"].as_bool

  # Regular update and upgrade
  run_command("apt", ["update", "-qq"], log)
  if config["apt"]["upgrade"].as_bool
    run_command("apt", ["upgrade", "-y", "-qq"], log)
  end

  # Check for dist-upgrade if enabled
  if config["apt"]["dist_upgrade"].as_bool
    # Check target from ~/.hackeros/hup.yaml
    target_file = "#{ENV["HOME"]}/.hackeros/hup.yaml"
    if File.exists?(target_file)
      target_yaml = YAML.parse(File.read(target_file))
      target_version = target_yaml["version"]?.try(&.as_s) || "unknown"
      target_codename = target_yaml["codename"]?.try(&.as_s) || "unknown"
      current_version, _ = get_current_debian_info

      if target_version > current_version
        log.info("Detected newer Debian version (#{target_version} / #{target_codename}). Performing dist-upgrade.")
        # Edit sources.list to new codename (WARNING: This can be risky!)
        sources_files = ["/etc/apt/sources.list"] + Dir.glob("/etc/apt/sources.list.d/*.list")
        sources_files.each do |file|
          if File.exists?(file)
            content = File.read(file)
            new_content = content.gsub(current_codename, target_codename)
            File.write(file, new_content)
            log.info("Updated sources in #{file} to #{target_codename}")
          end
        end
        # Now do full dist-upgrade
        run_command("apt", ["update", "-qq"], log)
        success, _, _ = run_command("apt", ["full-upgrade", "-y", "-qq"], log)
        if success
          # Update saved version
          save_current_version(target_version, target_codename)
        end
        return success
      else
        log.info("No newer version in config. Skipping dist-upgrade.")
      end
    else
      log.info("No target config at #{target_file}. Skipping dist-upgrade.")
    end
  end

  # Autoremove and autoclean
  if config["apt"]["autoremove"].as_bool
    run_command("apt", ["autoremove", "-y", "-qq"], log)
  end
  if config["apt"]["autoclean"].as_bool
    run_command("apt", ["autoclean", "-qq"], log)
  end

  true
end

# Update Flatpak
def update_flatpak(config : Hash, log : Logger) : Bool
  return true unless config["flatpak"]["enabled"].as_bool
  success, _, _ = run_command("flatpak", ["update", "-y", "--noninteractive"], log)
  success
end

# Update FWUPD
def update_fwupd(config : Hash, log : Logger) : Bool
  return true unless config["fwupd"]["enabled"].as_bool
  run_command("fwupdmgr", ["refresh", "--force"], log)
  success, _, _ = run_command("fwupdmgr", ["update", "-y"], log)
  success
end

# Update Snap
def update_snap(config : Hash, log : Logger) : Bool
  return true unless config["snap"]["enabled"].as_bool
  success, _, _ = run_command("snap", ["refresh"], log)
  success
end

def main
  # Setup logger
  log_file = "/var/log/hup.log" # Default, will override from config
  log = Logger.new(File.new(log_file, "a"))
  log.level = Logger::INFO

  # Load config from YAML
  config_file = "#{ENV["HOME"]}/.config/hacker/hup.yml"
  config = DEFAULT_CONFIG
  if File.exists?(config_file)
    user_config = YAML.parse(File.read(config_file)).as_h
    config = config.merge(user_config)
    log_file = config["log"]["file"].as_s if config["log"]? && config["log"]["file"]?
    log = Logger.new(File.new(log_file, "a")) # Reopen with new file if changed
    log.level = case config["log"]["level"].as_s.downcase
                when "debug" then Logger::DEBUG
                when "error" then Logger::ERROR
                else Logger::INFO
                end
  end

  # Load CSS styles and override config styles
  css_file = "#{ENV["HOME"]}/.config/hacker/hup.css"
  css_styles = parse_css(css_file)
  if css_styles.any?
    config["style"] = config["style"].merge({
      "info_color"    => css_styles["info-color"]? || config["style"]["info_color"],
      "error_color"   => css_styles["error-color"]? || config["style"]["error_color"],
      "success_color" => css_styles["success-color"]? || config["style"]["success_color"],
    })
  end

  # Note: Since this is background CLI, styles can be used if running manually with output,
  # e.g., puts "#{COLOR_CODES[config["style"]["info_color"].as_s]}Info message#{COLOR_CODES["reset"]}"
  # But for background, we log plain text.

  log.info("Hacker Updater started at #{Time.local}")

  # Get and save current version
  current_version, current_codename = get_current_debian_info
  save_current_version(current_version, current_codename)
  log.info("Current Debian: version #{current_version}, codename #{current_codename}")

  # Perform updates
  apt_success = update_apt(config, log, current_codename)
  flatpak_success = update_flatpak(config, log)
  fwupd_success = update_fwupd(config, log)
  snap_success = update_snap(config, log)

  overall_success = apt_success && flatpak_success && fwupd_success && snap_success

  # Check for reboot
  if reboot_required? && config["notify"]["enabled"].as_bool
    send_notification(config["notify"]["reboot_message"].as_s, log)
  end

  log.info("Hacker Updater finished. Success: #{overall_success}")
end

# Run main if not daemon or for testing
main
