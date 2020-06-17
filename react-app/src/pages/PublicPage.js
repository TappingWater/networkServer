import React from 'react';
import { Container } from 'reactstrap';

class PublicPage extends React.Component {
  render() {
    return (
    <Container>
      <h1>Welcome to a public page</h1>
      <div>
        This public page is accessible to anyone.
      </div>
    </Container>);
  }
}

export default PublicPage
