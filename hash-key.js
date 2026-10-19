const bcrypt = require("bcryptjs");
const readline = require("readline");

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
rl.question("Enter the access key to hash (input is visible): ", async (key) => {
  try {
    if (!key || key.length < 8) {
      console.error("Use an access key of at least 8 characters.");
      process.exitCode = 1;
    } else {
      const hash = await bcrypt.hash(key, 12);
      console.log("\nSet this environment variable on your server:\nACCESS_KEY_HASH=" + hash);
      console.log("Do not put the original key or this hash in frontend files or public repositories.");
    }
  } finally {
    rl.close();
  }
});
