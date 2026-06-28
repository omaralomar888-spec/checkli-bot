const { Client, GatewayIntentBits, SlashCommandBuilder, REST, Routes } = require("discord.js");
const axios = require("axios");

const DISCORD_TOKEN = process.env.DISCORD_TOKEN;
const CLIENT_ID = process.env.CLIENT_ID;
const VT_API_KEY = process.env.VT_API_KEY;

const client = new Client({
  intents: [GatewayIntentBits.Guilds]
});

const command = new SlashCommandBuilder()
  .setName("scan")
  .setDescription("افحص رابط وتأكد هل هو آمن أو ضار")
  .addStringOption(option =>
    option
      .setName("url")
      .setDescription("ضع الرابط هنا")
      .setRequired(true)
  );

async function scanUrl(url) {
  const submit = await axios.post(
    "https://www.virustotal.com/api/v3/urls",
    new URLSearchParams({ url }),
    {
      headers: {
        "x-apikey": VT_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
      }
    }
  );

  const analysisId = submit.data.data.id;

  await new Promise(resolve => setTimeout(resolve, 15000));

  const result = await axios.get(
    `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
    {
      headers: {
        "x-apikey": VT_API_KEY
      }
    }
  );

  return result.data.data.attributes.stats;
}

client.once("ready", async () => {
  console.log(`Logged in as ${client.user.tag}`);

  const rest = new REST({ version: "10" }).setToken(DISCORD_TOKEN);

  await rest.put(
    Routes.applicationCommands(CLIENT_ID),
    { body: [command.toJSON()] }
  );

  console.log("Slash command /scan registered");
});

client.on("interactionCreate", async interaction => {
  if (!interaction.isChatInputCommand()) return;
  if (interaction.commandName !== "scan") return;

  const url = interaction.options.getString("url");

  await interaction.reply("🔎 جاري فحص الرابط... انتظر قليلًا");

  try {
    const stats = await scanUrl(url);

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;

    let message = "";

    if (malicious > 0) {
      message =
        `❌ الرابط ضار\n\n` +
        `Malicious: ${malicious}\n` +
        `Suspicious: ${suspicious}\n` +
        `Harmless: ${harmless}`;
    } else if (suspicious > 0) {
      message =
        `⚠️ الرابط مشبوه\n\n` +
        `Malicious: ${malicious}\n` +
        `Suspicious: ${suspicious}\n` +
        `Harmless: ${harmless}`;
    } else {
      message =
        `✅ الرابط يبدو آمنًا\n\n` +
        `Malicious: ${malicious}\n` +
        `Suspicious: ${suspicious}\n` +
        `Harmless: ${harmless}`;
    }

    await interaction.editReply(message);
  } catch (error) {
    console.error(error.response?.data || error.message);
    await interaction.editReply("❌ صار خطأ أثناء الفحص. تأكد من الرابط أو API Key.");
  }
});

client.login(DISCORD_TOKEN);
