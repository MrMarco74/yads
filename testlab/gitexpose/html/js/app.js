// Application JavaScript — testlab git exposure target
// JS Secrets Scanner should find these patterns:

const config = {
    apiUrl: 'https://api.testlab.local',
    // Fake secrets for scanner testing
    googleApiKey: 'AIzaSyBcXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
    twilioAccountSid: 'AC1234567890abcdef1234567890abcdef',
    twilioAuthToken: '12345678901234567890123456789012',
    jwtSecret: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.faketoken',
    internalDbPassword: 'internal-db-p@ssw0rd-2024',
};

function init() {
    console.log('App initialized');
}
