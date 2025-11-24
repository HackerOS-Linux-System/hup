require "process"
require "file"
require "dir"
require "yaml"
require "json"
require "log"

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
    "enabled"      => true,
    "upgrade"      => true,
    "dist_upgrade" => false,
    "autoremove"   => true,
    "autoclean"    => true,
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
    "enabled"        => true,
    "reboot_message" => "HackerOS: Reboot required after updates!",
  },
  "log" => {
    "file"  => "/var/log/hup.log",
    "level" => "info",
  },
  "style" => {
    "info_color"    => "cyan",
    "error_color"   => "red",
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
def run_command(cmd : String, args : Array(String)) : {Bool, String, String}
  stdout = IO::Memory.new
  stderr = IO::Memory.new
  status = Process.run(cmd, args: args, output: stdout, error: stderr)
  out = stdout.to_s
  err = stderr.to_s
  if status.success?
    Log.info { "Command '#{cmd} #{args.join(" ")}' succeeded: #{out}" }
  else
    Log.error { "Command '#{cmd} #{args.join(" ")}' failed: #{err}" }
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
def send_notification(message : String)
  success, _, err = run_command("notify-send", ["-u", "critical", "Hacker Updater", message])
  unless success
    Log.error { "Notification failed: #{err}" }
  end
end
# Update APT
def update_apt(config : Hash(YAML::Any, YAML::Any), current_codename : String) : Bool
  apt_key = YAML::Any.new("apt")
  return true unless config[apt_key].as_h[YAML::Any.new("enabled")].as_bool
  # Regular update and upgrade
  run_command("apt", ["update", "-qq"])
  if config[apt_key].as_h[YAML::Any.new("upgrade")].as_bool
    run_command("apt", ["upgrade", "-y", "-qq"])
  end
  # Check for dist-upgrade if enabled
  if config[apt_key].as_h[YAML::Any.new("dist_upgrade")].as_bool
    # Check target from ~/.hackeros/hup.yaml
    home = if ENV.has_key?("SUDO_USER")
             "/home/#{ENV["SUDO_USER"]}"
           else
             ENV["HOME"]
           end
    target_file = "#{home}/.hackeros/hup.yaml"
    if File.exists?(target_file)
      target_yaml = YAML.parse(File.read(target_file))
      target_version = target_yaml.as_h[YAML::Any.new("version")]?.try(&.as_s) || "unknown"
      target_codename = target_yaml.as_h[YAML::Any.new("codename")]?.try(&.as_s) || "unknown"
      current_version, _ = get_current_debian_info
      if current_version != "unknown" && target_version != "unknown" && target_version.to_i > current_version.to_i
        Log.info { "Detected newer Debian version (#{target_version} / #{target_codename}). Performing dist-upgrade." }
        # Edit sources.list to new codename (WARNING: This can be risky!)
        sources_files = ["/etc/apt/sources.list"] + Dir.glob("/etc/apt/sources.list.d/*.list")
        sources_files.each do |file|
          if File.exists?(file)
            content = File.read(file)
            new_content = content.gsub(current_codename, target_codename)
            File.write(file, new_content)
            Log.info { "Updated sources in #{file} to #{target_codename}" }
          end
        end
        # Now do full dist-upgrade
        run_command("apt", ["update", "-qq"])
        success, _, _ = run_command("apt", ["full-upgrade", "-y", "-qq"])
        if success
          # Update saved version
          save_current_version(target_version, target_codename)
        end
        return success
      else
        Log.info { "No newer version in config. Skipping dist-upgrade." }
      end
    else
      Log.info { "No target config at #{target_file}. Skipping dist-upgrade." }
    end
  end
  # Autoremove and autoclean
  if config[apt_key].as_h[YAML::Any.new("autoremove")].as_bool
    run_command("apt", ["autoremove", "-y", "-qq"])
  end
  if config[apt_key].as_h[YAML::Any.new("autoclean")].as_bool
    run_command("apt", ["autoclean", "-qq"])
  end
  true
end
# Update Flatpak
def update_flatpak(config : Hash(YAML::Any, YAML::Any)) : Bool
  return true unless config[YAML::Any.new("flatpak")].as_h[YAML::Any.new("enabled")].as_bool
  success, _, _ = run_command("flatpak", ["update", "-y", "--noninteractive"])
  success
end
# Update FWUPD
def update_fwupd(config : Hash(YAML::Any, YAML::Any)) : Bool
  return true unless config[YAML::Any.new("fwupd")].as_h[YAML::Any.new("enabled")].as_bool
  run_command("fwupdmgr", ["refresh", "--force"])
  success, _, _ = run_command("fwupdmgr", ["update", "-y"])
  success
end
# Update Snap
def update_snap(config : Hash(YAML::Any, YAML::Any)) : Bool
  return true unless config[YAML::Any.new("snap")].as_h[YAML::Any.new("enabled")].as_bool
  success, _, _ = run_command("snap", ["refresh"])
  success
end
def main
  if LibC.getuid != 0
    puts "hup requires sudo"
    exit 1
  end
  # Determine the user's home directory even when run with sudo
  home = if ENV.has_key?("SUDO_USER")
           "/home/#{ENV["SUDO_USER"]}"
         else
           ENV["HOME"]
         end
  # Load config from YAML
  config_file = "#{home}/.config/hacker/hup.yml"
  default_config = YAML.parse(DEFAULT_CONFIG.to_yaml).as_h
  user_config = File.exists?(config_file) ? YAML.parse(File.read(config_file)).as_h : Hash(YAML::Any, YAML::Any).new
  config = default_config.merge(user_config)
  # Setup log
  log_key = YAML::Any.new("log")
  log_file = config[log_key].as_h[YAML::Any.new("file")].as_s
  level_str = config[log_key].as_h[YAML::Any.new("level")].as_s.downcase
  level = case level_str
          when "debug" then Log::Severity::Debug
          when "error" then Log::Severity::Error
          else Log::Severity::Info
          end
  file_backend = Log::IOBackend.new(File.open(log_file, "a"))
  console_backend = Log::IOBackend.new(STDOUT)
  Log.builder.clear
  Log.builder.bind("*", level, file_backend)
  Log.builder.bind("*", level, console_backend)
  # Load CSS styles and override config styles
  css_file = "#{home}/.config/hacker/hup.css"
  css_styles = parse_css(css_file)
  style_key = YAML::Any.new("style")
  config_style = config[style_key].as_h
  if css_styles.any?
    if info_color = css_styles["info-color"]?
      config_style[YAML::Any.new("info_color")] = YAML::Any.new(info_color)
    end
    if error_color = css_styles["error-color"]?
      config_style[YAML::Any.new("error_color")] = YAML::Any.new(error_color)
    end
    if success_color = css_styles["success-color"]?
      config_style[YAML::Any.new("success_color")] = YAML::Any.new(success_color)
    end
  end
  # Note: Since this is background CLI, styles can be used if running manually with output,
  # e.g., puts "#{COLOR_CODES[config["style"]["info_color"].as_s]}Info message#{COLOR_CODES["reset"]}"
  # But for background, we log plain text.
  Log.info { "Hacker Updater started at #{Time.local}" }
  # Get and save current version
  current_version, current_codename = get_current_debian_info
  save_current_version(current_version, current_codename)
  Log.info { "Current Debian: version #{current_version}, codename #{current_codename}" }
  # Perform updates
  apt_success = update_apt(config, current_codename)
  flatpak_success = update_flatpak(config)
  fwupd_success = update_fwupd(config)
  snap_success = update_snap(config)
  overall_success = apt_success && flatpak_success && fwupd_success && snap_success
  # Check for reboot
  notify_key = YAML::Any.new("notify")
  if reboot_required? && config[notify_key].as_h[YAML::Any.new("enabled")].as_bool
    send_notification(config[notify_key].as_h[YAML::Any.new("reboot_message")].as_s)
  end
  Log.info { "Hacker Updater finished. Success: #{overall_success}" }
end
# Run main if not daemon or for testing
main
