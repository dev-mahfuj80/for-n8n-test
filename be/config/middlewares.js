const _ = require("lodash");

module.exports = ({ env }) => {
  let corsOrigins = _.compact(env.array("CORS_ORIGINS", []));

  return [
    "strapi::logger",
    "strapi::errors",
    {
      name: "strapi::security",
      config: {
        contentSecurityPolicy: {
          useDefaults: true,
          directives: {
            "connect-src": ["'self'", "https:"],
            "img-src": ["'self'", "data:", "blob:", "*.singaporetestlab.com"],
            "media-src": ["'self'", "data:", "blob:"],
            upgradeInsecureRequests: null,
          },
        },
      },
    },
    {
      name: "strapi::cors",
      config: {
        // header: "*",
        enabled: true,
        origin: _.concat(
          ["http://localhost:3000", "http://localhost:1337"],
          corsOrigins
        ),
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
      },
    },
    "strapi::cors",
    "strapi::poweredBy",
    "strapi::query",
    "strapi::body",
    "strapi::session",
    "strapi::favicon",
    "strapi::public",
  ];
};
