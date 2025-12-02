// Test file - triggers multiple detections
// DO NOT RUN - this is for scanner testing only

// IOC string detection
const campaign = "Shai-Hulud test marker";

// Exfil endpoint detection  
const exfilUrl = "https://webhook.site/test-uuid";

// Malicious domain detection
const badDomain = "https://npm-stats.com/collect";

// Attacker wallet detection
const wallet = "0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976";

// Crypto theft function name
function checkethereumw() {
  return "test";
}

console.log("This file triggers scanner detections for testing");


