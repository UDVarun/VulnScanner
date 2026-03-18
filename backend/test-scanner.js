const { scanEndpoint } = require('./engines/scannerEngine.js');
async function run() {
  const findings = await scanEndpoint({
    url: 'http://google.com/url?q=https://example.com',
    method: 'GET',
    params: [{ name: 'usg', type: 'query' }, { name: 'q', type: 'query' }]
  });
  console.log(JSON.stringify(findings, null, 2));
}
run();
