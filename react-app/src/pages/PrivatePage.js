import React from 'react';
import { Container } from 'reactstrap';

class PrivatePage extends React.Component {
  render() {
    return (
    <Container>
      <h1>Welcome to a private page</h1>
      <div>
        You have successfully authenticated.
      </div>
      <div>
        This page is "private" only inasmuch as the front-end does not
        display it to unauthenticated users.  In a fully-fledged app,
        this page would now perform API requests that require authentication.
      </div>
    </Container>);
  }
}

export default PrivatePage
