// Jira Cloud basic authentication (email + API token) as a connector-pack auth script.
// Input: nothing (stdin is ignored). Secrets arrive as CA_SECRET_<NAME> environment variables.
// Output (stdout): {"headers": {"Authorization": "Basic …"}, "expiresIn": 3600}
/* global process, Buffer */
const email = process.env.CA_SECRET_EMAIL;
const token = process.env.CA_SECRET_API_TOKEN;
if (!email || !token) {
  process.stderr.write('secrets email and api_token are required\n');
  process.exit(1);
}
const basic = Buffer.from(`${email}:${token}`, 'utf8').toString('base64');
process.stdout.write(JSON.stringify({ headers: { Authorization: `Basic ${basic}` }, expiresIn: 3600 }));
