"use strict";
const { toPlainObject } = require("lodash/fp");

const {
  checkBadRequest,
} = require("../../utils");

module.exports = ({ nexus, strapi }) => {
  const { nonNull, inputObjectType } = nexus;

  const ResendOTPInput = inputObjectType({
    name: "ResendOTPInput",
    definition(t) {
      t.nonNull.string("identifier");
    },
  });

  return {
    type: nonNull("JSON"),

    args: {
      input: nonNull(ResendOTPInput),
    },

    async resolve(parent, args, context) {
      const { koaContext } = context;

      koaContext.request.body = toPlainObject(args.input);

      await strapi
        .plugin("users-permissions")
        .controller("auth")
        .resendOtp(koaContext);

      const output = koaContext.body;

      checkBadRequest(output);

      return output;
    },
  };
};
