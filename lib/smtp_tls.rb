require "openssl"
require "net/smtp"

Net::SMTP.class_eval do
  private
  alias_method :do_start_orig, :do_start
  def do_start(helodomain, user, secret, authtype)
    # try to extract parameter authtype
    authtype=authtype.to_s if (authtype.kind_of?(Symbol)) 
    if (authtype[0..3].downcase=="tls_")
      real_authtype=authtype[4..authtype.length-1]
      do_start_tls(helodomain, user, secret, real_authtype)
    else
      do_start_orig(helodomain, user,secret, authtype)
    end
  end
  
  def do_start_tls(helodomain, user, secret, authtype)
    
    raise IOError, 'SMTP session already started' if @started
    check_auth_args user, secret, authtype if user or secret

    sock = timeout(@open_timeout) { TCPSocket.open(@address, @port) }
    @socket = Net::InternetMessageIO.new(sock)
    @socket.read_timeout = 60 #@read_timeout

    check_response(critical { recv_response() })
    do_helo(helodomain)

    if starttls
      raise 'openssl library not installed' unless defined?(OpenSSL)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect
      @socket = Net::InternetMessageIO.new(ssl)
      @socket.read_timeout = 60 #@read_timeout
      do_helo(helodomain)
    end

    authenticate user, secret, authtype if user
    @started = true
  ensure
    unless @started
      # authentication failed, cancel connection.
      @socket.close if not @started and @socket and not @socket.closed?
      @socket = nil
    end
  end

  def do_helo(helodomain)
    begin
      if @esmtp
        ehlo helodomain
      else
        helo helodomain
      end
    rescue Net::ProtocolError
      if @esmtp
        @esmtp = false
        @error_occured = false
        retry
      end
      raise
    end
  end

  def starttls
    getok('STARTTLS') rescue return false
    return true
  end

  def quit
    begin
      getok('QUIT')
    rescue EOFError
    end
  end
end