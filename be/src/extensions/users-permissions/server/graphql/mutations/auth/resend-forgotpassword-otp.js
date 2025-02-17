"use strict";
const { toPlainObject } = require("lodash/fp");

const {
  checkBadRequest,
} = require("../../utils");

module.exports = ({ nexus, strapi }) => {
  const { nonNull, inputObjectType } = nexus;

  const ResendForgotPasswordOTPInput = inputObjectType({
    name: "ResendForgotPasswordOTPInput",
    definition(t) {
      t.nonNull.string("identifier");
    },
  });

  return {
    type: nonNull("JSON"),

    args: {
      input: nonNull(ResendForgotPasswordOTPInput),
    },

    async resolve(parent, args, context) {
      const { koaContext } = context;

      koaContext.request.body = toPlainObject(args.input);

      await strapi
        .plugin("users-permissions")
        .controller("auth")
        .resendForgotPasswordOtp(koaContext);

      const output = koaContext.body;

      checkBadRequest(output);

      return output;
    },
  };
};
