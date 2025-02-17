"use strict";

const { toPlainObject } = require("lodash/fp");

const {
  checkBadRequest,
} = require("../../utils");

module.exports = ({ nexus, strapi }) => {
  const { nonNull, inputObjectType } = nexus;

  const VerifyOtpInput = inputObjectType({
    name: "VerifyOtpInput",
    definition(t) {
      t.nonNull.string("identifier");
      t.nonNull.string("otpCode");
    },
  });

  return {
    type: nonNull("JSON"),

    args: {
      input: nonNull(VerifyOtpInput),
    },

    async resolve(parent, args, context) {
      const { koaContext } = context;
      koaContext.request.body = toPlainObject(args.input);

      await strapi
        .plugin("users-permissions")
        .controller("auth")
        .verifyOtp(koaContext);

      const output = koaContext.body;

      checkBadRequest(output);

      return output;
    },
  };
};
