// public URL, put in by create-react-app's webpack config
const publicUrl = process.env.PUBLIC_URL

const menus = {
    topbar : [
        { path: `${publicUrl}/`, label: "Home" },
    ],
    leftdropdowns : [
        {
            label: "Public",
            entries: [
              { path: `${publicUrl}/public`, label: "Public Content" }
            ]
        }
    ],
    rightdropdowns : [
        {
            label: "Private",
            onlyifauthenticated: true,
            entries: [
              { path: `${publicUrl}/protected`, label: "Private Content" }
            ]
        }
    ]
};

// To avoid same-origin issues, make API requests to origin.
// webpack devserver will proxy these requests, but you must specify
// a 'proxy' entry in package.json, see
// https://github.com/facebookincubator/create-react-app/blob/master/packages/react-scripts/template/README.md#proxying-api-requests-in-development
const apiPrefix = `${publicUrl}/api`

console.log(`Read configuration.  Public_URL: ${publicUrl}`)
// console.log(`apiPrefix:  ${apiPrefix}`)

export default { menus, apiPrefix, publicUrl }
