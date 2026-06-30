export const demoInvite = 'envoix:demo-clean-transfer-link';
export const demoLink = 'https://envoix.local/invite/demo-clean-transfer-link';

export const cliFlows = [
  {
    title: 'QR invite flow',
    description: 'Receiver prints a terminal QR and invite string; sender pastes the invite.',
    commands: [
      'cargo run -p envoix-cli -- receive --auto --output ./received',
      'cargo run -p envoix-cli -- send --invite "envoix:<base64url>" ./hello.txt',
    ],
  },
  {
    title: 'LAN mDNS shared-token flow',
    description: 'Receiver advertises on the LAN; sender discovers a compatible endpoint.',
    commands: [
      'cargo run -p envoix-cli -- receive --auto --output ./received --token "shared-token-123"',
      'cargo run -p envoix-cli -- send --enable-mdns --token "shared-token-123" ./hello.txt',
    ],
  },
  {
    title: 'Manual peer/token flow',
    description: 'Receiver prints the peer descriptor; sender passes the peer and shared token.',
    commands: [
      'cargo run -p envoix-cli -- receive --output ./received --token "shared-token-123"',
      'cargo run -p envoix-cli -- send --peer "192.168.1.5:<port>" --token "shared-token-123" ./hello.txt',
    ],
  },
];

export const supportedCliFeatures = [
  'One-file send and receive',
  'QR invite receive/send',
  'LAN mDNS discovery with shared token',
  'Manual peer descriptor plus token',
  'Resume-aware transfer state',
  'Persistent or ephemeral identity',
  'IPv4, IPv6, or dual-stack receive binding',
  'Configurable chunk size through config or ENVOIX_CHUNK_SIZE',
];

export const futureFacingFeatures = [
  'Relay or server fallback',
  'Real mobile camera QR scanning',
  'Folder and multi-file manifests',
  'Interactive pause/resume controls',
];
