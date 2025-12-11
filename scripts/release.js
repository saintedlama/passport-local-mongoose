#!/usr/bin/env node

const { execSync } = require('child_process');
const packageJson = require('../package.json');

function exec(command, exitOnError = true) {
  try {
    return execSync(command, { encoding: 'utf-8' }).trim();
  } catch (error) {
    if (!exitOnError) {
      throw new Error(`Command failed: ${command}\n${error.message}`);
    }

    console.error(`Error executing command: ${command}`);
    console.error(error.message);
    process.exit(1);
  }
}

function main() {
  // Check if we're in a git repository
  exec('git rev-parse --git-dir');

  // Check if we're on main branch
  const currentBranch = exec('git rev-parse --abbrev-ref HEAD');
  if (currentBranch !== 'main') {
    console.error(`Error: You must be on the 'main' branch to create a release. Current branch: ${currentBranch}`);
    process.exit(1);
  }

  // Check for uncommitted changes
  const status = exec('git status --porcelain');
  if (status) {
    console.error('Error: You have uncommitted changes. Please commit or stash them first.');
    process.exit(1);
  }

  exec('npm run build');
  exec('npm pack');

  const tagName = `v${packageJson.version}`;

  // Check if tag already exists
  const existingTag = exec(`git tag -l ${tagName}`, false);
  if (existingTag) {
    console.error(`Error: Tag ${tagName} already exists`);
    process.exit(1);
  }

  // Create the tag on main branch (before creating release branch)
  exec(`git tag ${tagName}`);
  console.log(`✓ Tag ${tagName} created on main branch`);

  // Push the tag to origin
  console.log('Pushing tag to GitHub...');
  exec(`git push origin ${tagName}`);
  console.log(`✓ Tag ${tagName} pushed to GitHub successfully`);


  console.log('\n🚀 Release completed!');
  console.log(`Release tag: ${tagName}`);
}

main();