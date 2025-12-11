import mongoose from 'mongoose';
import { UserModel } from './users.js';
import { parseArgs } from 'util';

async function main({ username, password }) {
  await mongoose.connect('mongodb://127.0.0.1:27017/passport-local-mongoose-example');

  console.log('Connected to MongoDB');

  console.log(`Registering user "${username}" with password "${password}"...`);
  await UserModel.register({ username }, password);

  console.log(`Registered user "${username}" with password "${password}"`);
}

const args = parseArgs({
  options: {
    username: { type: 'string', short: 'u' },
    password: { type: 'string', short: 'p' },
  },
});

if (!args.values.username || !args.values.password) {
  console.error('Usage: node register.js --username <username> --password <password>');
  process.exit(1);
}

main({ username: args.values.username, password: args.values.password })
  .then(() => {
    console.log('Done');
    process.exit(0);
  })
  .catch((err) => {
    console.error('Error:', err);
    process.exit(1);
  });
