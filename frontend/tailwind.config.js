/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        brand: { DEFAULT: "#2563eb", dark: "#1d4ed8" },
      },
    },
  },
  plugins: [],
};
