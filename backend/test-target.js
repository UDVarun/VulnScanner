const express = require('express');
const app = express();
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
  res.send(`
    <h1>Test Target App</h1>
    <a href="/search">Search Page</a>
    <a href="/profile?id=1">Profile Page</a>
  `);
});

app.get('/search', (req, res) => {
  const q = req.query.q || '';
  
  // Simulate SQLi
  if (q.includes("'") || q.includes("SLEEP")) {
     return res.status(500).send("SQL syntax error near '" + q + "'");
  }

  // Simulate XSS (Reflected)
  res.send(`
    <h2>Search Results for: ${q}</h2>
    <form action="/search" method="GET">
      <input type="text" name="q" value="${q}">
      <button>Search</button>
    </form>
  `);
});

app.get('/profile', (req, res) => {
  const id = req.query.id || '';
  
  // Path traversal simulation
  if (id.includes('../')) {
    return res.send("root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin");
  }

  res.send(`<h2>Profile ID: ${id}</h2>`);
});

app.listen(8080, () => {
  console.log('Dummy vulnerable target running on http://localhost:8080');
});
