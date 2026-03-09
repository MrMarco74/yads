const { ApolloServer, gql } = require('apollo-server');

const typeDefs = gql`
  type User {
    id: ID!
    username: String!
    email: String!
    password: String!
    role: String!
  }

  type Product {
    id: ID!
    name: String!
    price: Float!
    secret: String!
  }

  type Query {
    users: [User!]!
    user(id: ID!): User
    products: [Product!]!
    adminPanel: String!
  }

  type Mutation {
    login(username: String!, password: String!): String!
  }
`;

const users = [
  { id: '1', username: 'admin', email: 'admin@testlab.local', password: 'admin123', role: 'admin' },
  { id: '2', username: 'user1', email: 'user1@testlab.local', password: 'password1', role: 'user' },
];

const products = [
  { id: '1', name: 'Widget A', price: 9.99, secret: 'internal-sku-XYZ-001' },
  { id: '2', name: 'Widget B', price: 19.99, secret: 'internal-sku-XYZ-002' },
];

const resolvers = {
  Query: {
    users: () => users,
    user: (_, { id }) => users.find(u => u.id === id),
    products: () => products,
    adminPanel: () => 'Admin credentials: admin/admin123',
  },
  Mutation: {
    login: (_, { username, password }) => {
      const user = users.find(u => u.username === username && u.password === password);
      return user ? `token-${user.id}-fake` : 'invalid';
    },
  },
};

// introspection: true (default) — intentionally left enabled
// allowBatchedHttpRequests: true — enables batch attack vector
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true,
  csrfPrevention: false,
});

server.listen({ port: 4000, host: '0.0.0.0' }).then(({ url }) => {
  console.log(`GraphQL test server running at ${url}`);
});
