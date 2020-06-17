import React from 'react';
import { Route, Redirect } from 'react-router-dom';
import { connect } from 'react-redux';

import { isLoaded } from '../util/loadingObject';

// From https://github.com/gillisd/react-router-v4-redux-auth
const PrivateRoute = ({component: ComposedComponent, ...rest}) => {

  class Authentication extends React.Component {

    // redirect if not authenticated; otherwise, 
    // return the component input into <PrivateRoute />
    handleRender(props) {
      if (!this.props.authenticated) {
        return <Redirect to={{
          pathname: '/login',
          state: {
            from: props.location
          }
        }}/>
      } else {
        return <ComposedComponent {...props}/>
      }
    }

    render() {
      return (
        <Route {...rest} render={this.handleRender.bind(this)}/>
      )
    }
  }

  function mapStateToProps(state) {
    return {authenticated: isLoaded(state.auth)};
  }

  const AuthenticationContainer = connect(mapStateToProps)(Authentication)
  return <AuthenticationContainer/>
}

export { PrivateRoute };
