// Demo usage of @voiceflow/backend-utils
const utils = require('@voiceflow/backend-utils');

console.log("Voiceflow Backend Utils Demo Loaded");

try {
  if (utils?.Logger) {
    const logger = new utils.Logger({ level: 'info' });
    logger.info("Logger initialized from @voiceflow/backend-utils");
  } else {
    console.log("Imported @voiceflow/backend-utils successfully (version may not expose Logger in demo).");
  }
} catch (err) {
  console.error("Error loading package:", err.message);
}
