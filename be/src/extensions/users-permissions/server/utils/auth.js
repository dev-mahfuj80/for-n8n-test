const crypto = require('crypto');
const otpGenerator = require("otp-generator");
const { getService } = require('../utils');

const createOtpToken = async ({ payload: { userId } }) => {
  const otpCode = otpGenerator.generate(4, {
    digits: true,
    specialChars: false,
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
  });

  const verifyOtpToken = crypto
    .createHash("sha256")
    .update(otpCode)
    .digest("hex");

  // Token expires time set 1 minute  
  const verifyOtpExpires = Date.now() + 1 * 60 * 1000;

  await getService("user").edit(userId, {
    verifyOtpToken,
    verifyOtpExpires,
  });

  return { otpCode };
};

module.exports = {
  createOtpToken,
};
