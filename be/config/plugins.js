module.exports = ({ env }) => {
  let mailOptions = {
    host: env("SMTP_HOST", "smtp.gmail.com"),
    port: env("SMTP_PORT", 465),
    secure: true,
    auth: {
      user: env("MAIL_USERNAME"),
      pass: env("MAIL_PASSWORD"),
    },
    ignoreTLS: true,
    // tls: {
    //   // do not fail on invalid certs
    //   rejectUnauthorized: false,
    // },
  };

  let storageOptions = {
    provider: "strapi-provider-upload-minio-ce",
    providerOptions: {
      accessKey: env("MINIO_ACCESS_KEY", "2JrKuMYrtsT8EHXAhWnm"),
      secretKey: env(
        "MINIO_SECRET_KEY",
        "InzT3dJCM9zSV0ZaEw7QLgQaXJaIvcWVtYfcfTZd"
      ),
      bucket: env("MINIO_BUCKET", "grab-madic"),
      endPoint: env("MINIO_ENDPOINT", "minio-server.singaporetestlab.com"),
      port: env("MINIO_PORT", 443),
      useSSL: env("MINIO_USE_SSL", true),
      host: env("MINIO_HOST", "https://minio-server.singaporetestlab.com"),
      // expiry: env('MINIO_EXPIRY', 7 * 24 * 60 * 60), // default 7 days, unit: seconds, only work for private bucket
    },
  };

  return {
    email: {
      config: {
        provider: "nodemailer",
        providerOptions: mailOptions,
        settings: {
          defaultFrom: env("SEND_FROM", "dev.nexstack@gmail.com"),
          defaultReplyTo: env("SEND_TO", "dev.nexstack@gmail.com"),
        },
      },
    },
    graphql: {
      config: {
        endpoint: "/graphql",
        shadowCRUD: true,
        // playgroundAlways: true,
        amountLimit: 100,
        apolloServer: {
          tracing: false,
        },
      },
    },
    upload: {
      config: storageOptions,
    },
  };
};
