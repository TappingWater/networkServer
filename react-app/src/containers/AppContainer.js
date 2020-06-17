import React from 'react';
import { connect } from 'react-redux';
import TopNavBar from '../components/TopNavBar';
import Logout from '../components/Logout';
import LoginPage from '../pages/LoginPage';
import PublicPage from '../pages/PublicPage';
import NotFoundPage from '../pages/NotFoundPage';
import HomePage from '../pages/HomePage';
import PrivatePage from '../pages/PrivatePage';
import { PrivateRoute } from '../components/privateroute';

import { Switch, Route, withRouter } from 'react-router-dom';

import config from '../config/';

/** AppContainer renders the navigation bar on top and its
 * children in the main part of the page.  Its children will
 * be chosen based on the selected route.
 */
class AppContainer extends React.Component {
  render() {
    return (
        <div>
          <TopNavBar branding="CS3214 Demo App"
                     menus={config.menus} 
                     user={this.props.user} 
                     loginUrl={`${config.publicUrl}/login`}
                     logoutUrl={`${config.publicUrl}/logout`}
            />
          <div className="container-fluid marketing">
              <Switch>
                  <Route exact path={`${config.publicUrl}/`} component={HomePage} />
                  <Route path={`${config.publicUrl}/logout`} component={Logout} />
                  <Route path={`${config.publicUrl}/login`} component={LoginPage} />
                  <Route path={`${config.publicUrl}/public`} component={PublicPage} />
                  <PrivateRoute path={`${config.publicUrl}/protected`} component={PrivatePage} />
                  <Route component={NotFoundPage} />
              </Switch>
          </div>
        </div>
    );
  }
}

function mapStateToProps(state) {
  return {
    user: state.auth
  };
}

function mapDispatchToProps(dispatch) {
  return {
    dispatch
  };
}

export default withRouter(connect(mapStateToProps, mapDispatchToProps)(AppContainer));
