import React from 'react';
import PropTypes from 'prop-types';
import {
  Collapse,
  Navbar,
  NavbarToggler,
  NavbarBrand,
  Nav,
  NavItem,
  NavLink,
  UncontrolledDropdown,
  DropdownToggle,
  DropdownMenu,
  DropdownItem } from 'reactstrap';

// https://stackoverflow.com/questions/42372179/reactstrap-and-react-router-4-0-0-beta-6-active-navlink
import { NavLink as RRNavLink } from 'react-router-dom';

import { isLoaded } from '../util/loadingObject'

/* A helper component to render an array of dropdowns 
 * inside a <Nav> element 
 */
const DropDowns = (props) => {
    const user = props.user 
    const isAdmin = Boolean(Number(user.admin))

    return (<div>
      {props.dropdowns.map((dropdown, index) =>
         (!(dropdown.onlyifauthenticated || dropdown.onlyifadmin)
          || (isLoaded(user) &&
                (
                    (dropdown.onlyifauthenticated && !dropdown.onlyifadmin)
                 || (dropdown.onlyifadmin && isAdmin)
                )
             )
         ) &&
         <UncontrolledDropdown nav inNavbar key={index}>
            <DropdownToggle nav caret>
              {dropdown.label}
            </DropdownToggle>
            <DropdownMenu right>
                {dropdown.entries.map((item) =>
                  <DropdownItem key={item.path}>
                    <NavLink to={item.path} key={item.path} activeClassName="active" tag={RRNavLink}>
                        {item.label}
                    </NavLink>
                  </DropdownItem>
                )}
            </DropdownMenu>
         </UncontrolledDropdown>
      )}</div>)
}

/**
 * Navigation bar component
 */
class NavBar extends React.Component {
    static propTypes = {
        menus: PropTypes.object,
        user: PropTypes.object,
        branding: PropTypes.string,
    }

    constructor(props) {
        super(props);

        this.toggle = this.toggle.bind(this);
        this.state = {
          isOpen: false
        };
    }

    toggle() {
        this.setState({
            isOpen: !this.state.isOpen
        });
    }

    render() {
        const menus = this.props.menus
        const user = this.props.user
        return (
          <div>
            <Navbar color="light" light expand="md">
              <NavbarToggler onClick={this.toggle} />
              <NavbarBrand to="/">{this.props.branding}</NavbarBrand>
              <Collapse isOpen={this.state.isOpen} navbar>
                <Nav className="mr-auto" navbar>
                  {menus.topbar.map((item) =>
                     <NavItem key={item.path}>
                       <NavLink to={item.path} activeClassName="active" tag={RRNavLink}>
                         {item.label}
                       </NavLink>
                     </NavItem>
                  )}
                  { menus.leftdropdowns &&
                    <DropDowns className="mr-auto" dropdowns={menus.leftdropdowns} user={user} />
                  }
                </Nav>
                <Nav className="ml-auto">
                  { menus.rightdropdowns &&
                    <DropDowns className="ml-auto" dropdowns={menus.rightdropdowns} user={user} />
                  }

                  {isLoaded(user) ?
                    <NavItem>
                      <NavLink activeClassName="active" tag={RRNavLink} to={this.props.logoutUrl}>Logout ({user.sub})</NavLink>
                    </NavItem>
                  :
                    <NavItem>
                      <NavLink activeClassName="active" tag={RRNavLink} to={this.props.loginUrl}>Login</NavLink>
                    </NavItem>
                  } 
                </Nav>
              </Collapse>
            </Navbar>
          </div>
        );
    }
}

export default NavBar;
