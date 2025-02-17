"use strict";
const _ = require("lodash");

module.exports = {
  /**
   * An asynchronous register function that runs before
   * your application is initialized.
   *
   * This gives you an opportunity to extend code.
   */
  register(/*{ strapi }*/) {},

  /**
   * An asynchronous bootstrap function that runs before
   * your application gets started.
   *
   * This gives you an opportunity to set up your data model,
   * run jobs, or perform some special logic.
   */
  bootstrap({ strapi }) {
    const roles = [
      { id: 3, name: "Manufacture", description: "Manufacture / Distributor" },
      { id: 4, name: "Marchant", description: "Marchant / Retailer" },
    ];
    const createRoleAndPermission = async (role) => {
      const { id, name, description } = role;
      const type = name.toLowerCase();
      let result = await strapi
        .query("plugin::users-permissions.role")
        .findOne({ where: { type: type } });
      if (result == null) {
        result = await strapi.entityService.create(
          "plugin::users-permissions.role",
          {
            data: {
              id: id,
              name: name,
              description: description,
              type: type,
            },
          }
        );
      }
      return result;
    };

    const main = async () => {
      // First, create roles and permissions
      const rolePromises = _.map(roles, async (role) => {
        await createRoleAndPermission(role);
      });

      // Wait for all role creation promises to complete
      await Promise.all(rolePromises);
    };
    main().catch(console.error);
  },
};
