import React from 'react';
import { connect } from 'react-redux';
import PropTypes from 'prop-types';

import { Card, CardHeader, CardBody, Container, Row, Col } from 'reactstrap';
import { login } from '../actions/auth.js';
import { isLoading, isLoaded } from '../util/loadingObject'
import LoginForm from '../components/forms/LoginForm';
import { Redirect } from 'react-router-dom';

class LoginPage extends React.Component {
  static contextTypes = {
    router: PropTypes.object.isRequired
  }

  static propTypes = {
    user: PropTypes.object.isRequired
  }

  doLogin({username, password}) {
    this.props.dispatch(login(username, password));
  }

  render() {
    const user = this.props.user;
    const isAuthenticated = isLoaded(user);
    const { from } = this.props.location.state || { from: { pathname: "/" } };
    if (isAuthenticated) {
      return (<Redirect to={from} />);
    }

    return (
    <Container>
      <Row className="pb-5 pt-5">
        <Col xsoffset={0} xs={10} smoffset={4} sm={4}>
          <Card>
            <CardHeader><h3>Please log in</h3></CardHeader>
            <CardBody>
              <LoginForm
                loading={isLoading(user)}
                autherror={user.error}
                onSubmit={v => this.doLogin(v)} />
            </CardBody>
          </Card>
        </Col>
      </Row>
    </Container>
    );
  }
}

function mapStateToProps(state) {
  return {
    user: state.auth
  };
}

export default connect(mapStateToProps)(LoginPage);

