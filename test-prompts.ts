// test-prompts.ts
const PROMPTS = [
  "Write an intro for user whose email is john.doe@example.com",
  "Please send a reminder SMS to my personal number +1 800-555-0199 for the meeting.",
  "Retrieve the background check. The user SSN is 123-45-6789.",
  "Deposit the refund into my ethereum wallet 0x71C7656EC7ab88b098defB751B7401B5f6d8976F.",
  "Summarize the data located in our Cloud Storage URI s3://my-secret-company-bucket/data-logs.csv",
  "The DB is mongodb://admin:admin123@prod-cluster:27017/core_db. Analyze the schema.",
  "Can you write a polite email to them? by the way the key is - 15693ng903s",
  "Tell me how to configure the router. Default Password is admin123.",
  "The internal origin server IP is 192.168.1.15. How do I SSH into it?",
  "Here is my private key to sign the build: \n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB\n-----END RSA PRIVATE KEY-----",
  "Please use my credit card 4111-2222-3333-4444 to pay the vendor.",
  "Analyze this AWS key AKIAIOSFODNN7EXAMPLE to see if it's active.",
  "The secret key for the GitHub bot is ghp_16C7e42F292c6912E7710c838347Ae178B4a.",
  "Check why this JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c is throwing a 401 error."
];

async function runTests() {
  console.log("==========================================");
  console.log("🛡️  AEGIS PII & SECRET SANITIZATION TESTS 🛡️");
  console.log("==========================================");
  
  let passed = 0;
  
  for (let i = 0; i < PROMPTS.length; i++) {
    const prompt = PROMPTS[i];
    
    try {
      const response = await fetch('http://localhost:3000/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: prompt,
          user: 'test-user',
          policyMode: 'balanced'
        })
      });
      
      const result = await response.json();
      
      console.log(`\nTest #${i + 1}`);
      console.log(`[ORIGINAL]:  ${prompt}`);
      
      if (!result.rewritten_prompt || result.rewritten_prompt === '') {
         console.log(`[ACTION]:    ${result.action} (Prompt was blocked)`);
      } else {
         console.log(`[SANITIZED]: ${result.rewritten_prompt}`);
      }
      
      // Verification logic: Did it catch the sensitive part?
      if (
        result.rewritten_prompt.includes('john.doe@example.com') ||
        result.rewritten_prompt.includes('+1 800-555-0199') ||
        result.rewritten_prompt.match(/\d{3}-\d{2}-\d{4}/) ||
        result.rewritten_prompt.includes('0x71C7656EC7ab88b098defB751B7401B5f6d8976F') ||
        result.rewritten_prompt.includes('s3://') ||
        result.rewritten_prompt.includes('mongodb://') ||
        result.rewritten_prompt.includes('15693ng903s') ||
        result.rewritten_prompt.includes('admin123') ||
        result.rewritten_prompt.match(/192\.168\.1\.15/) ||
        result.rewritten_prompt.includes('MIIEpAIB') ||
        result.rewritten_prompt.includes('4111-2222-3333-4444') ||
        result.rewritten_prompt.includes('AKIAIOSFODNN7EXAMPLE') ||
        result.rewritten_prompt.includes('ghp_') ||
        result.rewritten_prompt.includes('eyJhbGciOiJ')
      ) {
         console.log(`❌ FAILED: Sensitive data leaked!`);
      } else {
         console.log(`✅ PASSED: Safely Redacted.`);
         passed++;
      }
      
    } catch (e) {
      console.error(`\n❌ Could not connect to API. Is 'npm run dev' running on port 3000?`);
      return;
    }
  }
  
  console.log("\n==========================================");
  console.log(`Result: ${passed}/${PROMPTS.length} Pass Rate (${(passed/PROMPTS.length)*100}%)`);
  console.log("==========================================");
}

runTests();
