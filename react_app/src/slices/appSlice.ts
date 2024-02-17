import { createSlice, PayloadAction } from "@reduxjs/toolkit";
import { RootState } from "../app/store";
import { Task } from "../types/types";

export interface AppState {
  editedTask: Task
}
const initialState: AppState = {
  editedTask: {
    id: '',
    title: '',
    description: '',
  }
}
export const appSlice = createSlice({
  name: 'app',
  initialState,
  reducers: {
    setEditedTask: (state, action: PayloadAction<Task>) => {
      state.editedTask = action.payload
    },
    resetEditedTask: (state) => {
      state.editedTask = initialState.editedTask
    }
  },
})
export const { setEditedTask, resetEditedTask } = 
  appSlice.actions

export const selectTask = (state: RootState) => state.app.editedTask

export default appSlice.reducer

