require 'rubygems'
require 'eventmachine'
require 'radiustar'
require 'socket'

module AuthenticationServer
  def post_init
    puts "Starting Radius Authentication Server."
    @dict = Radiustar::Dictionary.new 'dictionaries'
    @secret = 'ph887vYGaITI7l4z8Sj0nxKcO4P8iyy4'
  end

  def receive_data data
    packet = Radiustar::Packet.new @dict, Process.pid & 0xff, data
    puts "code #{packet.code}"
    puts "id #{packet.id}"
    puts "attributes #{packet.attributes}"

    password = packet.decode_attribute('Password', @secret)

    puts "password #{password}"
    response = Radiustar::Packet.new @dict, packet.id
    response.code = 'Access-Accept'
    response.set_attribute('Cisco/Cisco-AVPair', 'priv-lvl=15')
    response.gen_response_authenticator(@secret, packet.authenticator)
    send_data(response.pack)
  end
end

module AccountingServer
  
  def post_init
    puts "Starting Radius Accounting Server."
    @dict = Radiustar::Dictionary.new 'dictionaries'
    @secret = 'M9B6Iak4Bj4m0AB4gHE9wm0RjKI9663P'
  end

  def receive_data data
    packet = Radiustar::Packet.new @dict, Process.pid & 0xff, data
    puts "code #{packet.code}"
    puts "id #{packet.id}"
    puts "attributes #{packet.attributes}"
    #puts "authenticator #{packet.instance_variable_get :@authenticator}"
    puts "authenticator valid? #{packet.validate_acct_authenticator(@secret)}"
    response = Radiustar::Packet.new @dict, packet.id
    response.code = 'Accounting-Response'
    response.set_attribute('Acct-Session-Id', packet.attribute('Acct-Session-Id')) if packet.attribute('Acct-Session-Id')
    response.gen_response_authenticator(@secret, packet.authenticator)
    puts "response attributes #{response.attributes}"
    send_data(response.pack)
  end

end

def local_addr(af=Socket::AF_INET) 
  UDPSocket.open(af) { |s| s.connect(af==Socket::AF_INET ? '74.125.237.17' : '2404:6800:4006:802::1011', 1); s.addr.last }
end

EventMachine::run do

  EventMachine::open_datagram_socket(local_addr, 1812, AuthenticationServer)
  #EventMachine::open_datagram_socket(local_addr(Socket::AF_INET6), 1812, AuthenticationServer)
  EventMachine::open_datagram_socket(local_addr, 1813, AccountingServer)
  #EventMachine::open_datagram_socket(local_addr(Socket::AF_INET6), 1813, AccountingServer)

end

