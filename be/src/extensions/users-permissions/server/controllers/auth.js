"use strict";

/**
 * Auth.js controller
 *
 * @description: A set of functions called "actions" for managing `Auth`.
 */

/* eslint-disable no-useless-escape */
const crypto = require("crypto");
const _ = require("lodash");
const { concat, compact, isArray } = require("lodash/fp");
const utils = require("@strapi/utils");
const { getService } = require("../utils");
const {
  validateCallbackBody,
  validateRegisterBody,
  validateSendEmailConfirmationBody,
  validateForgotPasswordBody,
  validateResetPasswordBody,
  validateEmailConfirmationBody,
  validateChangePasswordBody,
} = require("./validation/auth");

/* custom added for otp */
const { createOtpToken } = require("../utils/auth");
const {
  contentTypes: { getNonWritableAttributes },
} = require("@strapi/utils");

const { sanitize } = utils;
const { ApplicationError, ValidationError, ForbiddenError } = utils.errors;
const sanitizeUser = (user, ctx) => {
  const { auth } = ctx.state;
  const userSchema = strapi.getModel("plugin::users-permissions.user");

  return strapi.contentAPI.sanitize.output(user, userSchema, { auth });
};

const sanitizeOutput = (user) => {
  const {
    password,
    resetPasswordToken,
    confirmationToken,
    verifyOtpToken,
    verifyOtpExpires,
    ...sanitizedUser
  } = user;
  return sanitizedUser;
};

const emailRegExp =
  /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

const getEmailSettings = async () => {
  const pluginStore = await strapi.store({
    type: "plugin",
    name: "users-permissions",
  });

  return {
    emailSettings: await pluginStore.get({ key: "email" }),
    advancedSettings: await pluginStore.get({ key: "advanced" }),
  };
};

const findUserByEmail = async (email) => {
  const user = await strapi.query("plugin::users-permissions.user").findOne({
    where: { email: email.toLowerCase() },
  });

  return user;
};

const sendResetPasswordEmail = async (emailToSend) => {
  try {
    await strapi.plugin("email").service("email").send(emailToSend);
  } catch (error) {
    console.error("Error sending user OTP to email:", error);
  }
};

const sendConfirmRegisterEmail = async (email) => {
  try {
    await strapi.plugin("email").service("email").send(email);
  } catch (error) {
    console.error("Error sending user OTP to email:", error);
  }
};

function extractNameFromEmail(email) {
  // Assuming the email address is in the format "name@example.com"
  const atIndex = email.indexOf("@");

  if (atIndex !== -1) {
    // Extract the part before the '@' symbol
    const name = email.slice(0, atIndex);

    // Replace any dots or underscores with spaces
    const formattedName = name.replace(/[\._]/g, " ");

    // Capitalize the first letter of each word
    const finalName = formattedName.replace(/\w\S*/g, function (word) {
      return word.charAt(0).toUpperCase() + word.substr(1).toLowerCase();
    });

    return finalName;
  } else {
    // Handle invalid email format
    return null;
  }
}

function isNullOrEmpty(value) {
  return value === null || value === undefined || value === "";
}

const sendRegisterConfirmationEmail = async (user, type) => {
  const userPermissionService = getService("users-permissions");
  const pluginStore = strapi.store({
    type: "plugin",
    name: "users-permissions",
  });
  const settings = await pluginStore
    .get({ key: "email" })
    .then((storeEmail) => storeEmail.email_confirmation.options);

  const { otpCode } = await createOtpToken({
    payload: { userId: user.id },
  });

  if (type == "register") {
    settings.message = `<p>Thank you for registering!</p>

        <p>You have to confirm your email address. Please use the OTP code below.</p>
        
        <p>${otpCode}</p>
        
        <p>Thanks.</p>`;
  }
  if (type == "resend") {
    settings.message = `<p>Resent OTP!</p>

        <p>You have to confirm your email address. Please use the OTP code below.</p>
        
        <p>${otpCode}</p>
        
        <p>Thanks.</p>`;
  }

  settings.object = `Account Comfirmation`;

  const emailBody = {
    to: user.email,
    from:
      settings.from.email && settings.from.name
        ? `${settings.from.name} <${settings.from.email}>`
        : undefined,
    replyTo: settings.response_email,
    subject: settings.object,
    text: settings.message,
    html: settings.message,
  };
  await sendConfirmRegisterEmail(emailBody);
};

const sendResendOtpEmail = async (user) => {
  const userPermissionService = getService("users-permissions");
  const pluginStore = await strapi.store({
    type: "plugin",
    name: "users-permissions",
  });
  const settings = await pluginStore
    .get({ key: "email" })
    .then((storeEmail) => storeEmail.email_confirmation.options);

  const apiPrefix = strapi.config.get("api.rest.prefix");

  const { otpCode } = await createOtpToken({
    payload: { userId: user.id },
  });
  settings.message = `<p>Resend OTP for Forgot Password!</p>

      <p>You have to reset your password. Please use the code below.</p>
      
      <p>${otpCode}</p>
      
      <p>Thanks.</p>`;

  settings.object = `Resend OTP`;

  const emailBody = {
    to: user.email,
    from:
      settings.from.email && settings.from.name
        ? `${settings.from.name} <${settings.from.email}>`
        : undefined,
    replyTo: settings.response_email,
    subject: settings.object,
    text: settings.message,
    html: settings.message,
  };
  await sendConfirmRegisterEmail(emailBody);
};

module.exports = ({ strapi }) => ({
  async callback(ctx) {
    const provider = ctx.params.provider || "local";
    const params = ctx.request.body;

    const store = strapi.store({ type: "plugin", name: "users-permissions" });
    const grantSettings = await store.get({ key: "grant" });

    const grantProvider = provider === "local" ? "email" : provider;

    if (!_.get(grantSettings, [grantProvider, "enabled"])) {
      throw new ApplicationError("This provider is disabled");
    }

    if (provider === "local") {
      await validateCallbackBody(params);

      const { identifier } = params;

      // Check if the user exists.
      const user = await strapi.db
        .query("plugin::users-permissions.user")
        .findOne({
          where: {
            provider,
            $or: [
              { email: identifier.toLowerCase() },
              { username: identifier },
            ],
          },
        });

      if (!user) {
        throw new ValidationError("Invalid identifier or password");
      }

      if (!user.password) {
        throw new ValidationError("Invalid identifier or password");
      }

      const validPassword = await getService("user").validatePassword(
        params.password,
        user.password
      );

      if (!validPassword) {
        throw new ValidationError("Invalid identifier or password");
      }

      const advancedSettings = await store.get({ key: "advanced" });
      const requiresConfirmation = _.get(
        advancedSettings,
        "email_confirmation"
      );

      if (requiresConfirmation && user.confirmed !== true) {
        throw new ApplicationError("Your account email is not confirmed");
      }

      if (user.blocked === true) {
        throw new ApplicationError(
          "Your account has been blocked by an administrator"
        );
      }

      return ctx.send({
        jwt: getService("jwt").issue({ id: user.id }),
        user: await sanitizeUser(user, ctx),
      });
    }

    // Connect the user with the third-party provider.
    try {
      const user = await getService("providers").connect(provider, ctx.query);

      if (user.blocked) {
        throw new ForbiddenError(
          "Your account has been blocked by an administrator"
        );
      }

      return ctx.send({
        jwt: getService("jwt").issue({ id: user.id }),
        user: await sanitizeUser(user, ctx),
      });
    } catch (error) {
      throw new ApplicationError(error.message);
    }
  },

  async changePassword(ctx) {
    if (!ctx.state.user) {
      throw new ApplicationError(
        "You must be authenticated to reset your password"
      );
    }

    const validations = strapi.config.get(
      "plugin::users-permissions.validationRules"
    );

    const { currentPassword, password } = await validateChangePasswordBody(
      ctx.request.body,
      validations
    );

    const user = await strapi.db
      .query("plugin::users-permissions.user")
      .findOne({ where: { id: ctx.state.user.id } });

    const validPassword = await getService("user").validatePassword(
      currentPassword,
      user.password
    );

    if (!validPassword) {
      throw new ValidationError("The provided current password is invalid");
    }

    if (currentPassword === password) {
      throw new ValidationError(
        "Your new password must be different than your current password"
      );
    }

    await getService("user").edit(user.id, { password });

    ctx.send({
      jwt: getService("jwt").issue({ id: user.id }),
      user: await sanitizeUser(user, ctx),
    });
  },

  async resetPassword(ctx) {
    const validations = strapi.config.get(
      "plugin::users-permissions.validationRules"
    );

    const { password, passwordConfirmation, code } =
      await validateResetPasswordBody(ctx.request.body, validations);

    if (password !== passwordConfirmation) {
      throw new ValidationError("Passwords do not match");
    }

    const user = await strapi.db
      .query("plugin::users-permissions.user")
      .findOne({ where: { resetPasswordToken: code } });

    if (!user) {
      throw new ValidationError("Incorrect code provided");
    }

    await getService("user").edit(user.id, {
      resetPasswordToken: null,
      password,
    });

    // Update the user.
    ctx.send({
      jwt: getService("jwt").issue({ id: user.id }),
      user: await sanitizeUser(user, ctx),
    });
  },

  async connect(ctx, next) {
    const grant = require("grant-koa");

    const providers = await strapi
      .store({ type: "plugin", name: "users-permissions", key: "grant" })
      .get();

    const apiPrefix = strapi.config.get("api.rest.prefix");
    const grantConfig = {
      defaults: {
        prefix: `${apiPrefix}/connect`,
      },
      ...providers,
    };

    const [requestPath] = ctx.request.url.split("?");
    const provider = requestPath.split("/connect/")[1].split("/")[0];

    if (!_.get(grantConfig[provider], "enabled")) {
      throw new ApplicationError("This provider is disabled");
    }

    if (!strapi.config.server.url.startsWith("http")) {
      strapi.log.warn(
        "You are using a third party provider for login. Make sure to set an absolute url in config/server.js. More info here: https://docs.strapi.io/developer-docs/latest/plugins/users-permissions.html#setting-up-the-server-url"
      );
    }

    // Ability to pass OAuth callback dynamically
    const queryCustomCallback = _.get(ctx, "query.callback");
    const dynamicSessionCallback = _.get(ctx, "session.grant.dynamic.callback");

    const customCallback = queryCustomCallback ?? dynamicSessionCallback;

    // The custom callback is validated to make sure it's not redirecting to an unwanted actor.
    if (customCallback !== undefined) {
      try {
        // We're extracting the callback validator from the plugin config since it can be user-customized
        const { validate: validateCallback } = strapi
          .plugin("users-permissions")
          .config("callback");

        await validateCallback(customCallback, grantConfig[provider]);

        grantConfig[provider].callback = customCallback;
      } catch (e) {
        throw new ValidationError("Invalid callback URL provided", {
          callback: customCallback,
        });
      }
    }

    // Build a valid redirect URI for the current provider
    grantConfig[provider].redirect_uri =
      getService("providers").buildRedirectUri(provider);

    return grant(grantConfig)(ctx, next);
  },

  // async forgotPassword(ctx) {
  //   const { email } = await validateForgotPasswordBody(ctx.request.body);

  //   const pluginStore = await strapi.store({
  //     type: "plugin",
  //     name: "users-permissions",
  //   });

  //   const emailSettings = await pluginStore.get({ key: "email" });
  //   const advancedSettings = await pluginStore.get({ key: "advanced" });

  //   // Find the user by email.
  //   const user = await strapi.db
  //     .query("plugin::users-permissions.user")
  //     .findOne({ where: { email: email.toLowerCase() } });

  //   if (!user || user.blocked) {
  //     return ctx.send({ ok: true });
  //   }

  //   // Generate random token.
  //   const userInfo = await sanitizeUser(user, ctx);

  //   const resetPasswordToken = crypto.randomBytes(64).toString("hex");

  //   const resetPasswordSettings = _.get(
  //     emailSettings,
  //     "reset_password.options",
  //     {}
  //   );
  //   const emailBody = await getService("users-permissions").template(
  //     resetPasswordSettings.message,
  //     {
  //       URL: advancedSettings.email_reset_password,
  //       SERVER_URL: strapi.config.get("server.absoluteUrl"),
  //       ADMIN_URL: strapi.config.get("admin.absoluteUrl"),
  //       USER: userInfo,
  //       TOKEN: resetPasswordToken,
  //     }
  //   );

  //   const emailObject = await getService("users-permissions").template(
  //     resetPasswordSettings.object,
  //     {
  //       USER: userInfo,
  //     }
  //   );

  //   const emailToSend = {
  //     to: user.email,
  //     from:
  //       resetPasswordSettings.from.email || resetPasswordSettings.from.name
  //         ? `${resetPasswordSettings.from.name} <${resetPasswordSettings.from.email}>`
  //         : undefined,
  //     replyTo: resetPasswordSettings.response_email,
  //     subject: emailObject,
  //     text: emailBody,
  //     html: emailBody,
  //   };

  //   // NOTE: Update the user before sending the email so an Admin can generate the link if the email fails
  //   await getService("user").edit(user.id, { resetPasswordToken });

  //   // Send an email to the user.
  //   await strapi.plugin("email").service("email").send(emailToSend);

  //   ctx.send({ ok: true });
  // },

  async forgotPassword(ctx) {
    try {
      let { email } = ctx.request.body;
      const { emailSettings, advancedSettings } = await getEmailSettings();

      // Assign header origin hostname.
      const headerOriginUrl = ctx.request.get("origin");

      // Check if the provided email is valid or not.
      const isEmail = emailRegExp.test(email);

      if (isEmail) {
        email = email.toLowerCase();
      } else {
        strapi.log.warn(
          `Forgot password request rejected. Invalid email format-[${email}].`
        );
        return ctx.badRequest("Please provide a valid email address");
      }

      // Find the user by email.
      const user = await findUserByEmail(email);

      // User not found.
      if (!user) {
        strapi.log.warn(
          `Forgot password request rejected. Invalid email or password for email [${email}].`
        );
        return ctx.badRequest("Invalid email or password. Try again !");
      }

      // User blocked.
      if (user.blocked) {
        strapi.log.warn(
          `Forgot password request rejected. Account with email [${email}] blocked by administrator.`
        );
        return ctx.badRequest(
          "Your account has been blocked by an administrator."
        );
      }

      // Generate otp code.
      const { otpCode } = await createOtpToken({
        payload: { userId: user.id },
      });

      const resetPasswordSettings = _.get(
        emailSettings,
        "reset_password.options",
        {}
      );

      const userInfo = await sanitizeOutput(user, ctx);

      const emailBody = getService("users-permissions").template(
        resetPasswordSettings.message,
        {
          URL: advancedSettings.email_reset_password,
          // URL: headerOriginUrl,
          // URL: new url.URL(`${headerOriginUrl}/auth/reset-password`),
          SERVER_URL: strapi.config.get("server.absoluteUrl"),
          ADMIN_URL: strapi.config.get("admin.absoluteUrl"),
          USER: userInfo.username,
          TOKEN: otpCode,
        }
      );

      const emailObject = getService("users-permissions").template(
        resetPasswordSettings.object,
        {
          USER: userInfo,
        }
      );

      const emailToSend = {
        to: user.email,
        from:
          resetPasswordSettings.from.email || resetPasswordSettings.from.name
            ? `${resetPasswordSettings.from.name} <${resetPasswordSettings.from.email}>`
            : undefined,
        replyTo: resetPasswordSettings.response_email,
        subject: emailObject,
        text: emailBody,
        html: emailBody,
      };

      // Send an email to the user.
      await sendResetPasswordEmail(emailToSend);

      strapi.log.info(`OTP sent to email [${user.email}] for password reset.`);
      ctx.send({
        data: {
          email: user.email,
          sent: true,
          message: "An OTP Code has been sent to your email.",
        },
      });
    } catch (error) {
      strapi.log.error(
        "Error occurred during forgot password request processing: ",
        error
      );
      ctx.badRequest(error.message);
    }
  },
  async register(ctx) {
    const pluginStore = await strapi.store({
      type: "plugin",
      name: "users-permissions",
    });

    const settings = await pluginStore.get({ key: "advanced" });

    if (!settings.allow_register) {
      throw new ApplicationError("Register action is currently disabled");
    }

    const { register } = strapi.config.get("plugin::users-permissions");
    const alwaysAllowedKeys = ["username", "password", "email", "roleName"];

    // Note that we intentionally do not filter allowedFields to allow a project to explicitly accept private or other Strapi field on registration
    const allowedKeys = compact(
      concat(
        alwaysAllowedKeys,
        isArray(register?.allowedFields) ? register.allowedFields : []
      )
    );

    // Check if there are any keys in requestBody that are not in allowedKeys
    const invalidKeys = Object.keys(ctx.request.body).filter(
      (key) => !allowedKeys.includes(key)
    );

    if (invalidKeys.length > 0) {
      // If there are invalid keys, throw an error
      throw new ValidationError(
        `Invalid parameters: ${invalidKeys.join(", ")}`
      );
    }

    const params = {
      ..._.pick(ctx.request.body, allowedKeys),
      provider: "local",
    };

    const validations = strapi.config.get(
      "plugin::users-permissions.validationRules"
    );

    await validateRegisterBody(params, validations);

    const { email, username, provider, roleName } = params;

    let default_role = roleName ? roleName : settings.default_role;

    const role = await strapi.db
      .query("plugin::users-permissions.role")
      .findOne({ where: { type: default_role } });

    if (!role) {
      throw new ApplicationError("Impossible to find the default role");
    }

    const identifierFilter = {
      $or: [
        { email: email.toLowerCase() },
        { username: email.toLowerCase() },
        { username },
        { email: username },
      ],
    };

    //Check existing user
    const existingUser = await strapi
      .query("plugin::users-permissions.user")
      .findOne({
        where: { ...identifierFilter, provider },
      });

    //Check existing user && iscomfirmed
    if (existingUser && !existingUser.confirmed) {
      await sendRegisterConfirmationEmail(existingUser, "register");
      return ctx.send({ user: sanitizeOutput(existingUser) });
    }

    const conflictingUserCount = await strapi.db
      .query("plugin::users-permissions.user")
      .count({
        where: { ...identifierFilter, provider },
      });

    if (conflictingUserCount > 0) {
      throw new ApplicationError("Email or Username are already taken");
    }

    if (settings.unique_email) {
      const conflictingUserCount = await strapi.db
        .query("plugin::users-permissions.user")
        .count({
          where: { ...identifierFilter },
        });

      if (conflictingUserCount > 0) {
        throw new ApplicationError("Email or Username are already taken");
      }
    }

    const newUser = {
      ...params,
      role: role.id,
      email: email.toLowerCase(),
      username,
      confirmed: !settings.email_confirmation,
    };

    const user = await getService("user").add(newUser);

    const sanitizedUser = await sanitizeUser(user, ctx);

    if (settings.email_confirmation) {
      try {
        await sendRegisterConfirmationEmail(sanitizedUser, "register");
        // await getService("user").sendConfirmationEmail(sanitizedUser);
      } catch (err) {
        strapi.log.error(err);
        throw new ApplicationError("Error sending confirmation email");
      }

      return ctx.send({ user: sanitizedUser });
    }

    const jwt = getService("jwt").issue(_.pick(user, ["id"]));

    return ctx.send({
      jwt,
      user: sanitizedUser,
    });
  },

  async emailConfirmation(ctx, next, returnUser) {
    const { confirmation: confirmationToken } =
      await validateEmailConfirmationBody(ctx.query);

    const userService = getService("user");
    const jwtService = getService("jwt");

    const [user] = await userService.fetchAll({
      filters: { confirmationToken },
    });

    if (!user) {
      throw new ValidationError("Invalid token");
    }

    await userService.edit(user.id, {
      confirmed: true,
      confirmationToken: null,
    });

    if (returnUser) {
      ctx.send({
        jwt: jwtService.issue({ id: user.id }),
        user: await sanitizeUser(user, ctx),
      });
    } else {
      const settings = await strapi
        .store({ type: "plugin", name: "users-permissions", key: "advanced" })
        .get();

      ctx.redirect(settings.email_confirmation_redirection || "/");
    }
  },

  async sendEmailConfirmation(ctx) {
    const { email } = await validateSendEmailConfirmationBody(ctx.request.body);

    const user = await strapi.db
      .query("plugin::users-permissions.user")
      .findOne({
        where: { email: email.toLowerCase() },
      });

    if (!user) {
      return ctx.send({ email, sent: true });
    }

    if (user.confirmed) {
      throw new ApplicationError("Already confirmed");
    }

    if (user.blocked) {
      throw new ApplicationError("User blocked");
    }

    await getService("user").sendConfirmationEmail(user);

    ctx.send({
      email: user.email,
      sent: true,
    });
  },

  async resendOtp(ctx) {
    const { identifier } = ctx.request.body;
    const userPermissionService = getService("users-permissions");
    const { emailSettings, advancedSettings } = await getEmailSettings();
    const pluginStore = await strapi.store({
      type: "plugin",
      name: "users-permissions",
    });
    const userSchema = strapi.getModel("plugin::users-permissions.user");

    const settings = await pluginStore
      .get({ key: "email" })
      .then((storeEmail) => storeEmail.email_confirmation.options);

    if (!identifier) {
      strapi.log.warn(
        "Registration failed. Email is required to send an OTP code."
      );
      return ctx.badRequest("Email is required to send OTP code.");
    }
    const user = await strapi.query("plugin::users-permissions.user").findOne({
      where: {
        $or: [{ email: identifier.toLowerCase() }, { username: identifier }],
      },
    });

    if (!user) {
      strapi.log.warn("Registration failed. Email address not found.");
      return ctx.badRequest("Email address not found.");
    }

    // const sanitizedUser = await sanitizeUser(user, ctx);
    try {
      await sendRegisterConfirmationEmail(user, "resend");

      strapi.log.info(`OTP code resent to email [${user.email}].`);
      return ctx.send({
        data: {
          email: user.email,
          sent: true,
          message: "An OTP Code has been resent.",
        },
      });
    } catch (error) {
      await getService("user").edit(user.id, {
        verifyOtpToken: null,
        verifyOtpExpires: null,
      });

      strapi.log.error(
        "Error sending OTP code to the email address: ",
        error.message
      );
      return ctx.internalServerError(
        "There was an error sending OTP Code to the email. Try again later."
      );
    }
  },

  async resendForgotPasswordOtp(ctx) {
    const { identifier } = ctx.request.body;
    const userPermissionService = getService("users-permissions");
    const { emailSettings, advancedSettings } = await getEmailSettings();
    const pluginStore = await strapi.store({
      type: "plugin",
      name: "users-permissions",
    });
    const userSchema = strapi.getModel("plugin::users-permissions.user");

    const settings = await pluginStore
      .get({ key: "email" })
      .then((storeEmail) => storeEmail.email_confirmation.options);

    if (!identifier) {
      strapi.log.warn("Resend failed. Email is required to send an OTP code.");
      return ctx.badRequest("Email is required to send OTP code.");
    }
    const user = await strapi.query("plugin::users-permissions.user").findOne({
      where: {
        $or: [{ email: identifier.toLowerCase() }, { username: identifier }],
      },
    });

    if (!user) {
      strapi.log.warn("Resend failed. Email address not found.");
      return ctx.badRequest("Email address not found.");
    }

    // const sanitizedUser = await sanitizeUser(user, ctx);
    try {
      await sendResendOtpEmail(user);

      strapi.log.info(`OTP code resent to email [${user.email}].`);
      return ctx.send({
        data: {
          email: user.email,
          sent: true,
          message: "An OTP Code has been resent.",
        },
      });
    } catch (error) {
      await getService("user").edit(user.id, {
        verifyOtpToken: null,
        verifyOtpExpires: null,
      });

      strapi.log.error("Error sending OTP code to the email address: ", error);
      return ctx.internalServerError(
        "There was an error sending OTP Code to the email. Try again later."
      );
    }
  },

  async verifyOtp(ctx) {
    const { identifier, otpCode } = ctx.request.body;
    if (!identifier || !otpCode) {
      strapi.log.warn(
        "OTP verification failed. Both email and OTP code are required."
      );
      return ctx.badRequest(
        "Email and OTP code are required to verify your account."
      );
    }

    const existed = await strapi
      .query("plugin::users-permissions.user")
      .findOne({
        where: {
          $or: [{ email: identifier.toLowerCase() }, { username: identifier }],
        },
        populate: [
          "role",
          "profile",
          "invest_profile",
          "consult_profile",
          "bd_profile",
        ],
      });

    if (!existed) {
      strapi.log.warn(
        `User not found with the provided email address [${identifier}].`
      );
      return ctx.notFound("There was no user with the provided email address.");
    }

    const hashedToken = crypto
      .createHash("sha256")
      .update(otpCode)
      .digest("hex");

    console.log("existing ", existed.verifyOtpToken);
    console.log("current ", hashedToken);

    // Check whether the generated otp token matched.
    if (hashedToken === existed.verifyOtpToken) {
      let expiresIn = new Date(existed.verifyOtpExpires).getTime();
      // Check whether the otp code has been expired.
      if (Date.now() > expiresIn) {
        strapi.log.warn(
          `OTP verification failed. Code has expired for email [${identifier}].`
        );
        return ctx.badRequest("Your OTP Code has been expired.");
      } else {
        let message = "";
        let resetPasswordToken = null;
        // Updated otp related fields to null and set new token for reset password.
        if (!existed.confirmed) {
          (message = "Your email has been verified."),
            await getService("user").edit(existed.id, {
              verifyOtpToken: null,
              verifyOtpExpires: null,
              confirmed: true,
            });
        }
        if (existed.confirmed) {
          message = "OTP code verified.";
          // Generate random token.
          const passwordToken = crypto.randomBytes(16).toString("hex");

          // Generate Jwt with expiry.
          resetPasswordToken = getService("jwt").issue(
            { passwordToken },
            {
              expiresIn: "300s", // it will be expired after 300s
            }
          );
          await getService("user").edit(existed.id, {
            verifyOtpToken: null,
            verifyOtpExpires: null,
            resetPasswordToken: resetPasswordToken,
          });
        }

        strapi.log.info(
          `OTP verification successful for email [${identifier}].`
        );
        // Then, send the authenticated token back to client.
        return ctx.send({
          data: {
            jwt: getService("jwt").issue({ id: existed.id }),
            message: message,
            code: resetPasswordToken,
            user: _.omit(existed, [
              "password",
              "confirmationToken",
              "verifyOtpToken",
              "verifyOtpExpires",
            ]),
          },
        });
      }
    } else {
      strapi.log.warn("OTP verification failed. Invalid OTP.");
      return ctx.badRequest("Please enter a valid OTP.");
    }
  },
});
