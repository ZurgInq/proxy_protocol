require "spec_helper"

RSpec.describe ProxyProtocol do
  it "has a version number" do
    expect(ProxyProtocol::VERSION).not_to be nil
  end
end
