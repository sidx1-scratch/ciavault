#!/usr/bin/env node
'use strict';

const { program } = require('commander');
const chalk       = require('chalk');
const ora         = require('ora');
const fs          = require('fs');
const path        = require('path');
const ciavault    = require('../src/index');
const utils       = require('../src/utils');

// ─── Banner ───────────────────────────────────────────────────────────────────

function banner() {
  console.log(chalk.cyan.bold(`
  ██████╗██╗ █████╗     ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
 ██╔════╝██║██╔══██╗    ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
 ██║     ██║███████║    ██║   ██║███████║██║   ██║██║     ██║   
 ██║     ██║██╔══██║    ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   
 ╚██████╗██║██║  ██║     ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   
  ╚═════╝╚═╝╚═╝  ╚═╝      ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   
`));
  console.log(chalk.gray('  🔐  File steganography + AES-256 + Three-layer rolling vault\n'));
}

function assertFile(filePath, label) {
  if (!fs.existsSync(filePath)) {
    console.error(chalk.red(`✖  ${label} not found: ${filePath}`));
    process.exit(1);
  }
}

function printResult(label, value) {
  console.log(`  ${chalk.gray(label.padEnd(18))} ${chalk.white(value)}`);
}

// ─── hide ─────────────────────────────────────────────────────────────────────

program
  .command('hide')
  .description('Hide a secret file inside a carrier file')
  .requiredOption('-c, --carrier <file>',  'Carrier file (image or any file)')
  .requiredOption('-s, --secret  <file>',  'Secret file to hide')
  .requiredOption('-o, --output  <file>',  'Output file path')
  .option('-m, --method <name>',           'lsb | eof | auto (default: auto)', 'auto')
  .option('-p, --passphrase <passphrase>', 'Encrypt the payload (AES-256-GCM)')
  .action(async (opts) => {
    banner();
    assertFile(opts.carrier, 'Carrier');
    assertFile(opts.secret,  'Secret');

    const carrierStat = fs.statSync(opts.carrier);
    const secretStat  = fs.statSync(opts.secret);

    console.log(chalk.bold('  Hiding file…\n'));
    printResult('Carrier',   `${opts.carrier}  ${chalk.gray(`(${utils.humanSize(carrierStat.size)})`)}`);
    printResult('Secret',    `${opts.secret}   ${chalk.gray(`(${utils.humanSize(secretStat.size)})`)}`);
    printResult('Method',    opts.method);
    printResult('Encrypted', opts.passphrase ? chalk.green('yes (AES-256-GCM)') : chalk.yellow('no'));
    printResult('Output',    opts.output);
    console.log();

    const spinner = ora({ text: 'Processing…', color: 'cyan' }).start();
    try {
      const outputBuf = await ciavault.hide({
        carrier: opts.carrier, secret: opts.secret,
        method: opts.method,   passphrase: opts.passphrase,
      });
      fs.writeFileSync(opts.output, outputBuf);
      spinner.succeed(chalk.green('Done!'));
      console.log();
      printResult('Output size', utils.humanSize(outputBuf.length));
      printResult('Saved to',    opts.output);
      console.log();
    } catch (err) {
      spinner.fail(chalk.red('Failed'));
      console.error(chalk.red(`\n  ✖  ${err.message}\n`));
      process.exit(1);
    }
  });

// ─── reveal ───────────────────────────────────────────────────────────────────

program
  .command('reveal')
  .description('Extract a hidden file from a carrier file')
  .requiredOption('-c, --carrier <file>',  'Carrier file containing the hidden payload')
  .option('-o, --output  <dir>',           'Directory to save the extracted file (default: .)', '.')
  .option('-m, --method <name>',           'lsb | eof | auto (default: auto)', 'auto')
  .option('-p, --passphrase <passphrase>', 'Passphrase to decrypt the payload')
  .option('--stdout',                      'Print extracted file contents to stdout')
  .action(async (opts) => {
    if (!opts.stdout) banner();
    assertFile(opts.carrier, 'Carrier');

    if (!opts.stdout) {
      console.log(chalk.bold('  Revealing hidden file…\n'));
      printResult('Carrier', opts.carrier);
      printResult('Method',  opts.method);
      console.log();
    }

    const spinner = opts.stdout ? null : ora({ text: 'Extracting…', color: 'cyan' }).start();
    try {
      const { filename, data } = await ciavault.reveal({
        carrier: opts.carrier, method: opts.method, passphrase: opts.passphrase,
      });

      if (opts.stdout) { process.stdout.write(data); return; }

      spinner.succeed(chalk.green('Payload found!'));
      const outPath = path.join(opts.output, filename);
      if (!fs.existsSync(opts.output)) fs.mkdirSync(opts.output, { recursive: true });
      fs.writeFileSync(outPath, data);

      console.log();
      printResult('Filename', filename);
      printResult('Size',     utils.humanSize(data.length));
      printResult('Saved to', outPath);
      console.log();
    } catch (err) {
      if (spinner) spinner.fail(chalk.red('Failed'));
      console.error(chalk.red(`\n  ✖  ${err.message}\n`));
      process.exit(1);
    }
  });

// ─── info ─────────────────────────────────────────────────────────────────────

program
  .command('info')
  .description('Check whether a file contains a hidden CIAVault payload')
  .requiredOption('-c, --carrier <file>', 'File to inspect')
  .option('-m, --method <name>',          'lsb | eof | auto (default: auto)', 'auto')
  .action(async (opts) => {
    banner();
    assertFile(opts.carrier, 'Carrier');

    console.log(chalk.bold('  Inspecting file…\n'));
    printResult('File',   opts.carrier);
    printResult('Method', opts.method);
    console.log();

    const spinner = ora({ text: 'Scanning…', color: 'cyan' }).start();
    try {
      const result = await ciavault.info({ carrier: opts.carrier, method: opts.method });
      spinner.stop();

      if (!result.hasPayload) {
        console.log(chalk.yellow('  ⚠  No CIAVault payload detected in this file.\n'));
        return;
      }
      console.log(chalk.green('  ✔  CIAVault payload found!\n'));
      printResult('Encrypted', result.encrypted ? chalk.yellow('yes') : chalk.green('no'));
      if (!result.encrypted) {
        printResult('Filename', result.filename);
        printResult('Size',     utils.humanSize(result.size));
      }
      console.log();
    } catch (err) {
      spinner.fail(chalk.red('Scan failed'));
      console.error(chalk.red(`\n  ✖  ${err.message}\n`));
      process.exit(1);
    }
  });

// ─── strip ────────────────────────────────────────────────────────────────────

program
  .command('strip')
  .description('Remove a hidden EOF payload from a carrier file, restoring the original')
  .requiredOption('-c, --carrier <file>', 'Carrier file with hidden payload')
  .requiredOption('-o, --output  <file>', 'Output path for the restored file')
  .action(async (opts) => {
    banner();
    assertFile(opts.carrier, 'Carrier');
    console.log(chalk.bold('  Stripping payload…\n'));

    const spinner = ora({ text: 'Working…', color: 'cyan' }).start();
    try {
      const eof   = require('../src/methods/eof');
      const buf   = fs.readFileSync(opts.carrier);
      const { strippedCarrier } = await eof.reveal(buf);
      fs.writeFileSync(opts.output, strippedCarrier);
      spinner.succeed(chalk.green('Done!'));
      console.log();
      printResult('Restored to', opts.output);
      printResult('Size',        utils.humanSize(strippedCarrier.length));
      console.log();
    } catch (err) {
      spinner.fail(chalk.red('Failed'));
      console.error(chalk.red(`\n  ✖  ${err.message}\n`));
      process.exit(1);
    }
  });

// ─── vault-encrypt ────────────────────────────────────────────────────────────

program
  .command('vault-encrypt')
  .description('Encrypt a file using the three-layer rolling vault (AES-256-GCM → SHA-256 → ChaCha20)')
  .requiredOption('-i, --input  <file>',  'File to encrypt')
  .requiredOption('-o, --output <file>',  'Output path for the encrypted blob')
  .option('-p, --password <password>',    'Use a specific password (default: auto-generate)')
  .action(async (opts) => {
    banner();
    assertFile(opts.input, 'Input');

    const plaintext = fs.readFileSync(opts.input);
    const password  = opts.password || ciavault.generatePassword();
    const analysis  = ciavault.analyzePassword(password);

    console.log(chalk.bold('  Three-layer vault encryption…\n'));
    printResult('Input',     `${opts.input}  ${chalk.gray(`(${utils.humanSize(plaintext.length)})`)}`);
    printResult('Password',  chalk.yellow(password));
    printResult('Structure', `${analysis.asciiCount} ASCII + ${analysis.unicodeCount} Unicode (${analysis.valid ? chalk.green('valid 60/40') : chalk.red('invalid')})`);
    printResult('Output',    opts.output);
    console.log();
    console.log(chalk.red('  ⚠  Save this password — it cannot be recovered!\n'));

    const spinner = ora({ text: 'Encrypting (3 layers)…', color: 'cyan' }).start();
    try {
      const ciphertext = await ciavault.encrypt(plaintext, password);
      fs.writeFileSync(opts.output, ciphertext);
      spinner.succeed(chalk.green('Done!'));
      console.log();
      printResult('Output size', utils.humanSize(ciphertext.length));
      printResult('Saved to',    opts.output);
      console.log();
    } catch (err) {
      spinner.fail(chalk.red('Failed'));
      console.error(chalk.red(`\n  ✖  ${err.message}\n`));
      process.exit(1);
    }
  });

// ─── vault-decrypt ────────────────────────────────────────────────────────────

program
  .command('vault-decrypt')
  .description('Decrypt a three-layer vault-encrypted blob')
  .requiredOption('-i, --input    <file>',     'Encrypted blob to decrypt')
  .requiredOption('-o, --output   <file>',     'Output path for the decrypted file')
  .requiredOption('-p, --password <password>', 'The password used during encryption')
  .action(async (opts) => {
    banner();
    assertFile(opts.input, 'Input');

    console.log(chalk.bold('  Three-layer vault decryption…\n'));
    printResult('Input',  opts.input);
    printResult('Output', opts.output);
    console.log();

    const spinner = ora({ text: 'Decrypting (3 layers)…', color: 'cyan' }).start();
    try {
      const ciphertext = fs.readFileSync(opts.input);
      const plaintext  = await ciavault.decrypt(ciphertext, opts.password);
      fs.writeFileSync(opts.output, plaintext);
      spinner.succeed(chalk.green('Done!'));
      console.log();
      printResult('Recovered size', utils.humanSize(plaintext.length));
      printResult('Saved to',       opts.output);
      console.log();
    } catch (err) {
      spinner.fail(chalk.red('Failed'));
      console.error(chalk.red(`\n  ✖  ${err.message}\n`));
      process.exit(1);
    }
  });

// ─── gen-password ─────────────────────────────────────────────────────────────

program
  .command('gen-password')
  .description('Generate a new 16-character 60/40 ASCII/Unicode vault password')
  .option('-n, --count <n>', 'How many passwords to generate', '1')
  .action((opts) => {
    banner();
    const count = Math.max(1, parseInt(opts.count, 10) || 1);
    console.log(chalk.bold(`  Generating ${count} password(s)…\n`));
    for (let i = 0; i < count; i++) {
      const pw = ciavault.generatePassword();
      const a  = ciavault.analyzePassword(pw);
      console.log(
        `  ${chalk.cyan((i + 1).toString().padStart(2))}  ${chalk.yellow(pw)}` +
        chalk.gray(`  (${a.asciiCount} ASCII + ${a.unicodeCount} Unicode)`)
      );
    }
    console.log();
  });

// ─── Run ──────────────────────────────────────────────────────────────────────

program
  .name('ciavault')
  .description('🔐 Steganography + three-layer rolling vault encryption')
  .version('2.0.0');

program.parse(process.argv);

if (!process.argv.slice(2).length) {
  banner();
  program.outputHelp();
}
