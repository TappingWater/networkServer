import { applyMiddleware, compose, createStore } from 'redux';
import thunk from 'redux-thunk';

import rootReducer from './reducers/root';

const createStoreWithMiddleware = compose(
  applyMiddleware(thunk),
  window.devToolsExtension ? window.devToolsExtension() : f => f
)(createStore);

const store = createStoreWithMiddleware(rootReducer);

export default store;

