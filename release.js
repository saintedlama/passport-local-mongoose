const shell = require('shelljs');

if (exec('git status --porcelain').stdout) {
  console.error('Git working directory not clean.');
  process.exit(2);
}

const versionIncrement = process.argv[process.argv.length -1];

if (versionIncrement != 'major' && versionIncrement != 'minor' && versionIncrement != 'patch') {
  console.error('Usage: node release.js major|minor|patch');
  process.exit(1);
}

exec('npm test');

exec('npm version ' + versionIncrement);
exec('git push');
exec('git push --tags');
exec('npm publish');

function exec(cmd) {
  const ret = shell.exec(cmd, { silent : true });

  if (ret.code != 0) {
    console.error(ret.stdout);
    console.error(ret.stderr);
    process.exit(1);
  }

  return ret;
}
