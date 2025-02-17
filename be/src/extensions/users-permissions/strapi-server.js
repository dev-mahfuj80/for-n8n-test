"use strict";

const { authEnhancement } = require("../../../config/features");

module.exports = (plugin) => {
  if (authEnhancement.enabled) {
    plugin.controllers = require("./server/controllers");
    plugin.routes = require("./server/routes");
    plugin.register = require("./server/register");
    plugin.middlewares = require("./server/middlewares");
  }

  plugin.contentTypes.role.schema.pluginOptions = {
    "content-manager": {
      visible: true,
    },
    "content-type-builder": {
      visible: true,
    },
  };

  return plugin;
};
