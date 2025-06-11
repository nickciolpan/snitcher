class CliSnitch < Formula
  desc "Terminal-based network connection monitor and firewall manager for macOS"
  homepage "https://github.com/nickciolpan/cli-snitch"
  url "https://github.com/nickciolpan/cli-snitch/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "REPLACE_WITH_ACTUAL_SHA256"
  license "MIT"
  head "https://github.com/nickciolpan/cli-snitch.git", branch: "main"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w"), "./cmd/cli-snitch"
  end

  def caveats
    <<~EOS
      CLI Snitch requires root privileges to monitor network connections and manage firewall rules.
      
      To start monitoring:
        sudo cli-snitch watch
      
      For system status:
        cli-snitch system-status
      
      Note: This tool requires macOS and uses pfctl for firewall integration.
    EOS
  end

  test do
    assert_match "CLI Snitch", shell_output("#{bin}/cli-snitch --help")
    assert_match "watch", shell_output("#{bin}/cli-snitch --help")
  end
end 