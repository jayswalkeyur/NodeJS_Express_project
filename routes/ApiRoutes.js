'use strict';

const auth = require("../middleware/auth")


module.exports = function(app) {
    const Api = require('../controllers/userController');

    app.route('/api/register')
        .post(Api.register_a_user);

    app.route('/api/login')
        .post(Api.login_a_user);

    app.route('/api/users')
        .get(Api.get_all_users);

};