require "./spec_helper"

# The client owns its session file. If `close` does not release the DeviceStore
# (and the lazily created Signal store on the same file), every reconnect leaks a
# descriptor plus SQLite's page cache: the application builds a new client after
# each disconnect and throws the old one away without access to its store. In
# production that produced 250 leaked descriptors and ~750 MB over four hours, at
# roughly one reconnect per minute.
#
# We count open descriptors rather than memory: a descriptor is an exact leak
# signal, while RSS is noisy because of the collector.
{% if flag?(:linux) %}
  private def open_fds : Int32
    Dir.children("/proc/self/fd").size
  end

  describe WhatsApp::Client do
    it "releases its session database descriptors on close" do
      path = File.join(Dir.tempdir, "wa-close-#{Random::Secure.hex(6)}.db")
      begin
        # The first client creates the session file, so its descriptors are not
        # part of the comparison.
        WhatsApp::Client.new(WhatsApp::Config.new(session_db: path)).close

        before = open_fds
        10.times { WhatsApp::Client.new(WhatsApp::Config.new(session_db: path)).close }
        after = open_fds

        (after - before).should eq(0)
      ensure
        [path, "#{path}-wal", "#{path}-shm"].each { |file| File.delete(file) if File.exists?(file) }
      end
    end

    it "is safe to close twice" do
      path = File.join(Dir.tempdir, "wa-close-twice-#{Random::Secure.hex(6)}.db")
      begin
        client = WhatsApp::Client.new(WhatsApp::Config.new(session_db: path))
        client.close
        client.close
      ensure
        [path, "#{path}-wal", "#{path}-shm"].each { |file| File.delete(file) if File.exists?(file) }
      end
    end
  end
{% else %}
  describe WhatsApp::Client do
    pending "counting open descriptors needs /proc (Linux)"
  end
{% end %}
