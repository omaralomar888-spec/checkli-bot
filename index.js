const {
  Client,
  GatewayIntentBits,
  SlashCommandBuilder,
  REST,
  Routes,
  EmbedBuilder
} = require("discord.js");

const axios = require("axios");
const FormData = require("form-data");

const DISCORD_TOKEN = process.env.DISCORD_TOKEN;
const CLIENT_ID = process.env.CLIENT_ID;
const VT_API_KEY = process.env.VT_API_KEY;

const client = new Client({
  intents: [GatewayIntentBits.Guilds]
});

const commands = [
  new SlashCommandBuilder()
    .setName("scan")
    .setDescription("فحص رابط")
    .addStringOption(option =>
      option.setName("url").setDescription("ضع الرابط هنا").setRequired(true)
    ),

  new SlashCommandBuilder()
    .setName("filescan")
    .setDescription("فحص ملف")
    .addAttachmentOption(option =>
      option.setName("file").setDescription("ارفع الملف هنا").setRequired(true)
    ),

  new SlashCommandBuilder()
    .setName("hash")
    .setDescription("فحص Hash")
    .addStringOption(option =>
      option.setName("hash").setDescription("MD5 / SHA1 / SHA256").setRequired(true)
    ),

  new SlashCommandBuilder()
    .setName("domain")
    .setDescription("فحص دومين")
    .addStringOption(option =>
      option.setName("domain").setDescription("example.com").setRequired(true)
    ),

  new SlashCommandBuilder()
    .setName("ip")
    .setDescription("فحص IP")
    .addStringOption(option =>
      option.setName("ip").setDescription("8.8.8.8").setRequired(true)
    )
];

function buildEmbed(title, stats, reportUrl) {
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const undetected = stats.undetected || 0;

  let status = "✅ يبدو آمنًا";
  let color = 0x2ecc71;

  if (malicious > 0) {
    status = "❌ ضار";
    color = 0xe74c3c;
  } else if (suspicious > 0) {
    status = "⚠️ مشبوه";
    color = 0xf1c40f;
  }

  return new EmbedBuilder()
    .setTitle(title)
    .setDescription(status)
    .setColor(color)
    .addFields(
      { name: "Malicious", value: String(malicious), inline: true },
      { name: "Suspicious", value: String(suspicious), inline: true },
      { name: "Harmless", value: String(harmless), inline: true },
      { name: "Undetected", value: String(undetected), inline: true }
    )
    .setFooter({ text: "CheckLi Security Scanner" })
    .setTimestamp()
    .setURL(reportUrl);
}

async function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

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
  await wait(15000);

  const result = await axios.get(
    `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
    { headers: { "x-apikey": VT_API_KEY } }
  );

  const encodedUrlId = Buffer.from(url)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  return {
    stats: result.data.data.attributes.stats,
    reportUrl: `https://www.virustotal.com/gui/url/${encodedUrlId}`
  };
}

async function scanFile(fileUrl, fileName) {
  const fileResponse = await axios.get(fileUrl, {
    responseType: "arraybuffer"
  });

  const form = new FormData();
  form.append("file", Buffer.from(fileResponse.data), fileName);

  const submit = await axios.post(
    "https://www.virustotal.com/api/v3/files",
    form,
    {
      headers: {
        ...form.getHeaders(),
        "x-apikey": VT_API_KEY
      },
      maxBodyLength: Infinity
    }
  );

  const analysisId = submit.data.data.id;
  await wait(20000);

  const result = await axios.get(
    `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
    { headers: { "x-apikey": VT_API_KEY } }
  );

  return {
    stats: result.data.data.attributes.stats,
    reportUrl: `https://www.virustotal.com/gui/file/${result.data.meta.file_info.sha256}`
  };
}

async function scanHash(hash) {
  const result = await axios.get(
    `https://www.virustotal.com/api/v3/files/${hash}`,
    { headers: { "x-apikey": VT_API_KEY } }
  );

  return {
    stats: result.data.data.attributes.last_analysis_stats,
    reportUrl: `https://www.virustotal.com/gui/file/${hash}`
  };
}

async function scanDomain(domain) {
  const result = await axios.get(
    `https://www.virustotal.com/api/v3/domains/${domain}`,
    { headers: { "x-apikey": VT_API_KEY } }
  );

  return {
    stats: result.data.data.attributes.last_analysis_stats,
    reportUrl: `https://www.virustotal.com/gui/domain/${domain}`
  };
}

async function scanIp(ip) {
  const result = await axios.get(
    `https://www.virustotal.com/api/v3/ip_addresses/${ip}`,
    { headers: { "x-apikey": VT_API_KEY } }
  );

  return {
    stats: result.data.data.attributes.last_analysis_stats,
    reportUrl: `https://www.virustotal.com/gui/ip-address/${ip}`
  };
}

client.once("ready", async () => {
  console.log(`Logged in as ${client.user.tag}`);

  const rest = new REST({ version: "10" }).setToken(DISCORD_TOKEN);

  await rest.put(
    Routes.applicationCommands(CLIENT_ID),
    { body: commands.map(command => command.toJSON()) }
  );

  console.log("CheckLi commands registered");
});

client.on("interactionCreate", async interaction => {
  if (!interaction.isChatInputCommand()) return;

  try {
    if (interaction.commandName === "scan") {
      const url = interaction.options.getString("url");
      await interaction.reply("🔎 جاري فحص الرابط...");
      const data = await scanUrl(url);
      await interaction.editReply({
        content: "",
        embeds: [buildEmbed("🔗 نتيجة فحص الرابط", data.stats, data.reportUrl)]
      });
    }

    if (interaction.commandName === "filescan") {
      const file = interaction.options.getAttachment("file");
      await interaction.reply("📁 جاري فحص الملف...");
      const data = await scanFile(file.url, file.name);
      await interaction.editReply({
        content: "",
        embeds: [buildEmbed("📁 نتيجة فحص الملف", data.stats, data.reportUrl)]
      });
    }

    if (interaction.commandName === "hash") {
      const hash = interaction.options.getString("hash");
      await interaction.reply("🔐 جاري فحص الهاش...");
      const data = await scanHash(hash);
      await interaction.editReply({
        content: "",
        embeds: [buildEmbed("🔐 نتيجة فحص الهاش", data.stats, data.reportUrl)]
      });
    }

    if (interaction.commandName === "domain") {
      const domain = interaction.options.getString("domain");
      await interaction.reply("🌐 جاري فحص الدومين...");
      const data = await scanDomain(domain);
      await interaction.editReply({
        content: "",
        embeds: [buildEmbed("🌐 نتيجة فحص الدومين", data.stats, data.reportUrl)]
      });
    }

    if (interaction.commandName === "ip") {
      const ip = interaction.options.getString("ip");
      await interaction.reply("📡 جاري فحص IP...");
      const data = await scanIp(ip);
      await interaction.editReply({
        content: "",
        embeds: [buildEmbed("📡 نتيجة فحص IP", data.stats, data.reportUrl)]
      });
    }
  } catch (error) {
    console.error(error.response?.data || error.message);

    if (interaction.replied || interaction.deferred) {
      await interaction.editReply("❌ صار خطأ أثناء الفحص. تأكد من المدخل أو من API Key.");
    } else {
      await interaction.reply("❌ صار خطأ أثناء الفحص.");
    }
  }
});

client.login(DISCORD_TOKEN);
