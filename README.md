`@asymmetrik/node-fhir-server-vista`
====================================

## Intro
This project is an example project built on `@asymmetrik/node-fhir-server-core` and has a Vista backend storing sample data. It's built with the ability to run in docker. To get started developing in Docker, see [Getting Started with Docker](#getting-started-with-docker).

## Getting Started with Docker

1. Install the latest [Docker Community Edition](https://www.docker.com/community-edition) for your OS if you do not already have it installed.
2. Create a new file `.local-secrets/auth.secrets` and fill in the values from `.local-secrets/auth.example`.
3. Run `docker-compose up`.

## Next Steps
Once you have this up and running. You should see the following output:

```shell
... - info: App listening on port: 3000 # or whichever port you used
... - info: FHIR Server successfully started.
```

At this point you can now start testing the endpoints. Depending what profiles you opt into, certain routes will be available.

You can view the routes enabled based on which service methods you provide over at [`@asymmetrik/node-fhir-server-core`](https://github.com/Asymmetrik/node-fhir-server-core#profiles).

The url the server will be running at will partially depend on your configuration. For local development, the default is `http://localhost:3000`. You can of course change the port in the `docker-compose.yml` or the `env.json`. You can also enable https by providing SSL certs. If you want to do this you must first generate them, see [Generate self signed certs](https://github.com/Asymmetrik/node-fhir-server-core/blob/master/.github/CONTRIBUTING.md#generate-self-signed-certs). Then, add the path to them in your config by setting `SSL_KEY` and `SSL_CERT` as ENV variable's, adding them in `docker-compose.yml`, or adding them to `env.json`. This will allow the app to run on `https://localhost:3000`. Note the link is for generating self signed certs, you should not use those for production. You can verify the path is set correctly by logging out the fhirServerConfig in `index.js`.


## Getting Started with Authorization

All resource endpoints are secured.  You will need to supply a valid access token with valid scopes in order to view the resource.  In this project, we have added a stubbed EHR authorization server you can use to create an access token.  You will need to have access to an EHR authorization server for your live environment.

There are two endpoints you need to access to generate a token.  Please refer to the SMART Authorization Guide (http://docs.smarthealthit.org/authorization) for more information.

You will first need to be granted a code.  The EHR decides whether to grant or deny access.  This decision is communicated to the app when the EHR authorization server returns an authorization code.  Authorization codes are short-lived, usually expiring within around one minute.  The code is sent when the EHR authorization server redirects the browser to the app’s redirect_uri, with the following URL parameters:

```
Location: http://ehr/authorize?
		response_type=code&
		client_id=app-client-id&
		redirect_uri=https://app/after-auth&
		launch=xyz123&
		scope=launch patient/Observation.read patient/Patient.read openid profile&
		state=98wrghuwuogerg97&
		aud=https://ehr/fhir
```

Once the server is up and populated with our seed data, try this URL in your browser if you don't have a SMART client application.
http://localhost:3000/authorize?client_id=xyz123&redirect_uri=http://localhost:3000/&response_type=code&state=43220320&scope=launch patient/*.read openid&aud=http://localhost:3000

You should see your browser redirect you back to localhost with a code and state in your url.  This is how you know if you have been granted access to the resource.  The format should look like this.

```
Location: https://app/after-auth?
		code=123abc&
		state=98wrghuwuogerg97
```

After obtaining an authorization code, the app trades the code for an access token via HTTP POST to the EHR authorization server’s token endpoint URL, using content-type application/x-www-form-urlencoded.

```
POST /token HTTP/1.1
Host: ehr
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
code=123abc
redirect_uri=https://app/after-auth
```

Lets give this a try on our server.
Using any request builder (i.e. Postman), create a new POST request with the code you obtained during the previous step.  You have a short time to use that code so if it has expired, you will need to be granted a new one.

```
POST http://localhost:3000

Content-Type: application/x-www-form-urlencoded
grant_type=authorization_code
code=<code you obtained from previous step>
redirect_uri=http://localhost:3000
```

If granted access, you should now have a valid token you can use to view the resources.  Depending on the authorization service you use, the format may differ.  The response should look something like this:
```
{
	"access_token": "i8hweunweunweofiwweoijewiwe",
	"token_type": "bearer",
	"expires_in": 3600,
	"scope": "patient/Observation.read patient/Patient.read",
	"state": "98wrghuwuogerg97"
}
```

Now you should have access to the Patient and Observation resources.  Using your request builder, create a new GET request with the required Authorization header.  For example:

```
GET http://localhost:3000/dstu2/Patient/1
Authorization: Bearer <access_token>
```

You should get back the Patient record.
```
{
  "resourceType": "Patient",
  "birthTime": ...
}
```

For more information regarding Authorization and scopes, please refer to http://docs.smarthealthit.org/.

## Commands
There are several npm scripts setup that may be useful. In docker, the syntax should be `docker-compose run <service> yarn <command>` or `docker-compose exec <service> yarn <command>`. Use `docker-compose exec` if you already have the app running in another terminal instance, otherwise use `docker-compose run` to run it once.

The commands are as follows:

* `start` - Run in production mode with NODE_ENV set to `production`. Use this when deploying.
* `nodemon` - Run in development mode with NODE_ENV set to `development`. This uses nodemon to restart the server when any js files in `src` are changed.
* `test` - Runs all of our test commands (via the 'test:ci' command), with NODE_ENV set to `test`. This is used for CI.
* `test:ci` - Convenience command which runs test:prepare-db, test:lint, and test:jest. You should not run this command, run the `test` command instead because it set's NODE_ENV correctly for testing.
* `test:lint` - Runs eslint against `fhir/src` with rules defined in the `.eslintrc`.
* `test:jest` - Runs tests using the [Jest](https://facebook.github.io/jest/) framework. It will run any tests in a `__tests__` directory or with the naming convention `<anything>.test.js`.
* `test:prepare-db` - This will reset and reinsert all the sample data into Mongo. This way you have a decent amount of data to work with when running your tests. When this is run via the `test` command, it will set the NODE_ENV for you. If you are running it independently, set the NODE_ENV before using.
* `populate` - This allows you to populate the database. One thing to keep in mind when using this, if the NODE_ENV is not set, it will default to the production db name. When you invoke this through docker, it will set NODE_ENV to `development` for you except when running tests, it will then use `test`. When running in node, you may need to manually set it to which ever environment you need it to be in. The db names are defined in the `env.json` file. This command also accepts some extra flags.
	* `-h` or `--help` - Prints help to the console.
	* `-p` or `--profiles` - Comma separated list of profiles to insert. For example, `-p Patient,Observation`.
	* `-a` or `-all` - Insert all the sample data that we have.
	* `-r` or `--reset` - Reset each collection before an insert. This will essentially drop the collection before creating it and inserting documents into it.

#### Example commands

```shell
# Docker
docker-compose exec fhir yarn test
docker-compose exec fhir yarn populate -r -a
```

## Deployment
This package uses an env.json to define some values for local development and they should be used for local development only. You need to make sure these are overridden before deploying `@asymmetrik/node-fhir-server-vista`. The following environment variables must be set before deploying:

```shell
VISTA_HOSTNAME
VISTA_DB_NAME
...(MORE)
```

## Having trouble with something?
If you have questions specific to Docker, Node, or Vista, please consider asking on Stack Overflow.  They already have a lot of support on these topics. If your questions is related to the FHIR specification, please review that documentation at [https://www.hl7.org/fhir/](https://www.hl7.org/fhir/). Any questions related to this specific package, please ask in the issues section. Also, if you think you are experiencing a bug or see something incorrect with the spec, please file an issue so we can help you as soon as we can.

## Want to Contribute?
Please see the [CONTRIBUTING.md](./.github/CONTRIBUTING.md) for contributing guidelines.

## License
`@asymmetrik/fhir-server-vista` is [MIT licensed](./LICENSE).
