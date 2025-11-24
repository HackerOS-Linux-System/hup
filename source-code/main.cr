require "process"

def run_command(cmd : String, args : Array(String))
  process = Process.new(cmd, args, output: Process::Redirect::Pipe, error: Process::Redirect::Pipe)
  status = process.wait
  {status.success?, process.output.gets_to_end, process.error.gets_to_end}
end

def update_apt
  # Update APT quietly
  success, out, err = run_command("apt", ["update", "-qq"])
  unless success
    puts "APT update failed: #{err}"
    return false
  end

  success, out, err = run_command("apt", ["upgrade", "-y", "-qq"])
  unless success
    puts "APT upgrade failed: #{err}"
    return false
  end

  # Optional: autoremove and autoclean
  run_command("apt", ["autoremove", "-y", "-qq"])
  run_command("apt", ["autoclean", "-qq"])

  true
end

def update_flatpak
  success, out, err = run_command("flatpak", ["update", "-y", "--noninteractive"])
  unless success
    puts "Flatpak update failed: #{err}"
    return false
  end
  true
end

def main
  # Run as background process, but since it's a service, it will be managed by systemd
  # Redirect output to /dev/null or log if needed, but for quiet, we use quiet flags

  if update_apt && update_flatpak
    # Success, but no output needed
  else
    # Log errors somewhere if desired, e.g., to syslog or file
  end
end

main if Process.ppid != 1  # Prevent running directly if not needed, but for testing
