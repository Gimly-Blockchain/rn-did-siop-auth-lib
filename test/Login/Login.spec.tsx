import React from "react";
import { fireEvent, render } from '@testing-library/react-native';

import { Login } from "../../src/Login";

test('Fort submit credentials', () => {
  const mockFn = jest.fn();

  const {getByPlaceholderText, getByA11yRole} = render(
    <Login onSubmit={mockFn}/>
  );

  const username = getByPlaceholderText('Username');
  const password = getByPlaceholderText('Password');
  const button = getByA11yRole('button')

  fireEvent.changeText(username, 'Test');
  fireEvent.changeText(password, 'test123');
  fireEvent.press(button);

  expect(mockFn).toBeCalledWith({username: 'Test', password: 'test123'});
});
