import React from 'react';
import { Redirect } from 'react-router-dom';
import store from '../store';

class Logout extends React.Component {
    componentWillMount() {
        // normally, we would inform the server just in case.
        document.cookie = "auth_token=";
        store.dispatch({ type: "LOGOUT" });
    }

    render() {
        return (<Redirect to="/" />);
    }
}

export default Logout;
