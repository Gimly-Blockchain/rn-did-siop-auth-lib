import React, { useState } from 'react';
import { Button, Text, TextInput, View } from 'react-native';

export const Login = ({ onSubmit }) => {
  const [data, setData] = useState({ username: '', password: '' });
  return (
    <View>
      <Text>Username</Text>
      <TextInput
        editable={true}
        placeholder={'Username'}
        onChangeText={(text) => setData({ ...data, username: text })}
      />
      <Text>Password</Text>
      <TextInput
        editable={true}
        secureTextEntry={true}
        placeholder={'Password'}
        onChangeText={(text) => setData({ ...data, password: text })}
      />
      <Button title={'Submit'} onPress={() => onSubmit(data)} />
    </View>
  );
};
